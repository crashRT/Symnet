package org.change.v2.executor.clickabstractnetwork

import org.change.symbolicexec.verification.Rule
import org.change.v2.abstractnet.generic.NetworkConfig
import org.change.v2.analysis.memory.{MemorySpace, State}
import org.change.v2.analysis.processingmodels.instructions.{InstructionBlock, NoOp}
import org.change.v2.analysis.processingmodels.{LocationId, Instruction}
import org.change.v2.executor.clickabstractnetwork.executionlogging.{NoLogging, ExecutionLogger}
import org.change.v2.executor.clickabstractnetwork.verificator.PathLocation
import org.change.v2.analysis.z3.Z3Util
import org.change.v2.util.canonicalnames._
import org.change.utils.abstractions._
import z3.scala.Z3AST

/**
 * Author: Radu Stoenescu
 * Don't be a stranger,  symnetic.7.radustoe@spamgourmet.com
 *
 * An execution context is determined by the instructions it can execute and
 * a set of states that were explored.
 *
 * A port is a String id, that maps to an instruction.
 */
case class ClickExecutionContext(
                           instructions: Map[LocationId, Instruction],
                           links: Map[LocationId, LocationId],
                           okStates: List[State],
                           failedStates: List[State],
                           stuckStates: List[State],
                           checkInstructions: Map[LocationId, Instruction] = Map.empty,
                           logger: ExecutionLogger = NoLogging
) {
  def setLogger(newLogger: ExecutionLogger): ClickExecutionContext = copy(logger = newLogger)

  /**
   * Merges two execution contexts.
   * @param that
   * @return
   */
  def +(that: ClickExecutionContext) = copy(
    this.instructions ++ that.instructions,
    this.links ++ that.links,
    this.okStates ++ that.okStates,
    this.failedStates ++ that.failedStates,
    this.stuckStates ++ that.stuckStates,
    this.checkInstructions ++ that.checkInstructions
  )

  /**
   * Is there any state further explorable ?
   * @return
   */
  def isDone: Boolean = okStates.isEmpty

  /**
   * Calls execute until nothing can be explored further more. (The result is a done Execution Context)
   * @param verbose
   * @return
   */
  def untilDone(verbose: Boolean): ClickExecutionContext = if (isDone) this else this.execute(verbose).untilDone(verbose)

  def execute(verbose: Boolean = false): ClickExecutionContext = {
    val (ok, fail, stuck) = okStates.map(s => {
      val stateLocation = s.location
      val instr = instructions.getOrElse(stateLocation, NoOp)

      // 1. Execute the instruction on current port.
      val r1 = instr(s, verbose)
      val (toCheck, r2) = r1._1.partition(s => checkInstructions.contains(s.location))
      val r3 = toCheck.map(s => checkInstructions(s.location)(s,verbose)).unzip

      // 2. Forward packet, if a link from this port location exists.
      // Detect forwarding loops via Z3 subsumption on IP src/dst fields:
      // When revisiting a location, check if !n & o is unsatisfiable for
      // IPSrc/IPDst (new state's IP space subsumes old state's IP space → loop).
      // This handles traditional routing loops with TTL decrement because TTL
      // is intentionally outside the compared packet space. NAT/rewrites that
      // change source or destination addresses change the compared state.
      val (candidateOkStates, loopFailedStates) =
        (r2 ++ r3._1.flatten).foldLeft((List.empty[State], List.empty[State])) {
          case ((cands, loops), s) =>
            // We don't forward packets which have changed their location after
            // executing the instruction.
            if (s.location == stateLocation && links.contains(stateLocation)) {
              val nextLocation = links(stateLocation)
              if (s.history.contains(nextLocation) &&
                  s.locationStates.getOrElse(nextLocation, Nil).exists { prevMem =>
                    ClickExecutionContext.isIpForwardingLoop(prevMem, s.memory)
                  }) {
                val loopState = State(s.memory, nextLocation :: s.history,
                  Some(s"Routing loop detected @ $nextLocation"), s.instructionHistory,
                  s.locationStates)
                (cands, loopState :: loops)
              } else {
                (s.forwardTo(nextLocation) :: cands, loops)
              }
            } else {
              (s :: cands, loops)
            }
        }
      val newFailStates = r1._2 ++ r3._2.flatten ++ loopFailedStates

      // Out of all candidate OK states, those which didn't change their
      // location are considered stuck.
      val (newOkStates, newStuckStates) =
        candidateOkStates.partition(_.location != stateLocation)

      (newOkStates, newFailStates, newStuckStates)
    }).unzip3

    useAndReturn(copy(
      okStates = ok.flatten,
      failedStates = failedStates ++ fail.flatten,
      stuckStates = stuckStates ++ stuck.flatten
    ), {ctx: ClickExecutionContext => logger.log(ctx)})
  }

  // TODO: Move to a logger
  def concretizeStates: String = (stuckStates ++ okStates).map(_.memory.concretizeSymbols).mkString("\n----------\n")

}

object ClickExecutionContext {

  // Relative offsets of IPSrc/IPDst within the L3 tag
  private val IpSrcRelOffset = 96
  private val IpDstRelOffset = 128

  private val ComparedIpFields = Seq(
    (IpSrcRelOffset, "IPSrc"),
    (IpDstRelOffset, "IPDst")
  )

  /**
   * Check whether the IP src/dst packet space of oldMem is contained in newMem,
   * i.e. whether old & !new is unsatisfiable for IPSrc/IPDst fields.
   *
   * The formula for each field includes both the current value expression
   * (field == expression) and the expression constraints. This matters for
   * rewrites to constants, which carry no constraints but still define a
   * singleton packet space.
   *
   * If unsatisfiable: every packet matching old also matches new → loop.
   * Returns false when either state lacks the compared IP fields.
   */
  def isIpForwardingLoop(oldMem: MemorySpace, newMem: MemorySpace): Boolean = {
    val ctx = Z3Util.z3Context

    def ipFieldFormula(mem: MemorySpace, relOffset: Int, fieldName: String): Option[Z3AST] =
      mem.memTags.get("L3").flatMap { l3Base =>
        val offset = l3Base + relOffset
        for {
          mo <- mem.rawObjects.get(offset)
          v  <- mo.value
        } yield {
          val fieldAst = ctx.mkConst(s"loop-detection-$fieldName", Z3Util.defaultSort)
          val (valueAst, _) = v.e.toZ3()
          val clauses = ctx.mkEq(fieldAst, valueAst) :: v.cts.map(_.z3Constrain(valueAst))
          ctx.mkAnd(clauses: _*)
        }
      }

    def ipStateFormula(mem: MemorySpace): Option[Z3AST] = {
      val fieldFormulas = ComparedIpFields.map {
        case (relOffset, fieldName) => ipFieldFormula(mem, relOffset, fieldName)
      }
      if (fieldFormulas.exists(_.isEmpty)) None
      else Some(ctx.mkAnd(fieldFormulas.flatten: _*))
    }

    val oldFormula = ipStateFormula(oldMem).getOrElse(return false)
    val newFormula = ipStateFormula(newMem).getOrElse(return false)

    // Check: old AND NOT(new) is unsatisfiable?
    val solver = Z3Util.solver
    solver.assertCnstr(oldFormula)
    solver.assertCnstr(ctx.mkNot(newFormula))
    solver.check() == Some(false)
  }

  /**
   * Builds a symbolic execution context out of a single click config file.
   *
   * @param networkModel
   * @param verificationConditions
   * @param includeInitial
   * @return
   */
  def fromSingle( networkModel: NetworkConfig,
                  verificationConditions: List[List[Rule]] = Nil,
                  includeInitial: Boolean = true,
                  initialIsClean: Boolean = false): ClickExecutionContext = {
    // Collect instructions for every element.
    val instructions = networkModel.elements.values.foldLeft(Map[LocationId, Instruction]())(_ ++ _.instructions)
    // Collect check instructions corresponding to network rules.
    val checkInstructions = verificationConditions.flatten.map( r => {
        networkModel.elements(r.where.element).outputPortName(r.where.port) -> InstructionBlock(r.whatTraffic)
      }).toMap
    // Create forwarding links.
    val links = networkModel.paths.flatMap( _.sliding(2).map(pcp => {
      val src = pcp.head
      val dst = pcp.last
      networkModel.elements(src._1).outputPortName(src._3) -> networkModel.elements(dst._1).inputPortName(dst._2)
    })).toMap
    // TODO: This should be configurable.
    val initialStates = if (includeInitial) {
      if (initialIsClean)
        List(State.clean.forwardTo(networkModel.entryLocationId))
      else
        List(State.bigBang.forwardTo(networkModel.entryLocationId))
    } else Nil

    new ClickExecutionContext(instructions, links, initialStates, Nil, Nil, checkInstructions)
  }

  def buildAggregated(
            configs: Iterable[NetworkConfig],
            interClickLinks: Iterable[(String, String, Int, String, String, Int)],
            verificationConditions: List[List[Rule]] = Nil,
            startElems: Option[Iterable[(String, String, Int)]] = None): ClickExecutionContext = {
    // Create a context for every network config.
    val ctxes = configs.map(ClickExecutionContext.fromSingle(_, includeInitial = false))
    // Keep the configs for name resolution.
    val configMap: Map[String, NetworkConfig] = configs.map(c => c.id.get -> c).toMap
    // Add forwarding links between click files.
    val links = interClickLinks.map(l => {
      val ela = l._1 + "-" + l._2
      val elb = l._4 + "-" + l._5
      configMap(l._1).elements(ela).outputPortName(l._3) -> configMap(l._4).elements(elb).inputPortName(l._6)
    }).toMap
    // Collect check instructions corresponding to network rules.
    val checkInstructions = verificationConditions.flatten.map( r => {
      val elementName = r.where.vm + "-" + r.where.element
      configMap(r.where.vm).elements(elementName).outputPortName(r.where.port) -> InstructionBlock(r.whatTraffic)
    }).toMap
    // Create initial states
    val startStates = startElems match {
      case Some(initialPoints) => initialPoints.map(ip =>
        State.bigBang.forwardTo(configMap(ip._1).elements(ip._1 + "-" + ip._2).inputPortName(ip._3)))
      case None => List(State.bigBang.forwardTo(configs.head.entryLocationId))
    }
    // Build the unified execution context.
    ctxes.foldLeft(new ClickExecutionContext(Map.empty, links, startStates.toList, Nil, Nil, checkInstructions))(_ + _)
  }
}
