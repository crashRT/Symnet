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
      // Detect forwarding/L2 loops via Z3 subsumption on IP src/dst fields:
      // When revisiting a location, check if !n & o is unsatisfiable for
      // IPSrc/IPDst (new state's IP space subsumes old state's IP space → loop).
      // This handles routing loops with TTL decrement or SNAT correctly because
      // TTL/source changes do not affect the IPDst-based routing decision.
      // DNAT redirects (IPDst changes) are correctly NOT flagged as loops.
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

  /**
   * Check whether the IP src/dst packet space of newMem is subsumed by oldMem,
   * i.e. whether !n & o is unsatisfiable for IPSrc/IPDst fields.
   *
   * If unsatisfiable: every packet matching old also matches new → the routing
   * decision hasn't changed → forwarding/L2 loop detected.
   *
   * Returns false (no loop) when either state has no IP constraints (insufficient
   * information) or when the IP destination has changed (e.g. DNAT redirect).
   */
  def isIpForwardingLoop(oldMem: MemorySpace, newMem: MemorySpace): Boolean = {
    val ctx = Z3Util.z3Context

    // Resolve absolute offsets of IPSrc/IPDst using the L3 memory tag
    val l3Base = oldMem.memTags.getOrElse("L3", 0)
    val ipFieldAbsOffsets = Seq(l3Base + IpSrcRelOffset, l3Base + IpDstRelOffset)

    // Collect Z3 ASTs for IP field constraints from a memory space
    def ipConstraintASTs(mem: MemorySpace): Seq[Z3AST] =
      ipFieldAbsOffsets.flatMap { offset =>
        for {
          mo <- mem.rawObjects.get(offset)
          v  <- mo.value
          if v.cts.nonEmpty
        } yield {
          val (ast, _) = v.e.toZ3()
          val conjuncts = v.cts.map(_.z3Constrain(ast))
          if (conjuncts.size == 1) conjuncts.head
          else ctx.mkAnd(conjuncts: _*)
        }
      }

    val oldConstraints = ipConstraintASTs(oldMem)
    if (oldConstraints.isEmpty) return false  // no IP info → can't determine

    val newConstraints = ipConstraintASTs(newMem)
    // Unconstrained new state covers everything → old ⊆ new → loop
    if (newConstraints.isEmpty) return true

    // Check: old AND NOT(new) is unsatisfiable?
    val solver = Z3Util.solver
    oldConstraints.foreach(solver.assertCnstr)
    val newConjunction =
      if (newConstraints.size == 1) newConstraints.head
      else ctx.mkAnd(newConstraints: _*)
    solver.assertCnstr(ctx.mkNot(newConjunction))
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
