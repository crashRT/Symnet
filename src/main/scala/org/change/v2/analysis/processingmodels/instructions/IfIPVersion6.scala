package org.change.v2.analysis.processingmodels.instructions

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.processingmodels.Instruction
import org.change.v2.util.canonicalnames._

/**
 * Dispatch on the IP version of the packet (the 4-bit field at L3+0, shared by
 * IPv4 and IPv6).
 *
 * The packets Mosaic injects carry a constant version (State.bigBang /
 * bigBang6), so only one branch runs, the state is left untouched, and no
 * failed state is recorded for the branch that does not apply.  `If` would
 * add the version constraint to every state and report the other branch as an
 * unsatisfiable-constraint failure on every classifier atom.
 *
 * A symbolic version falls back to `If`, forking with the constraint.  A
 * packet with no L3 version field (no IP header) takes the IPv4 branch, where
 * the IPv4 field reads are not allocated and the `If` falls to its else.
 */
case class IfIPVersion6(thenWhat: Instruction, elseWhat: Instruction) extends Instruction {
  override def apply(s: State, v: Boolean): (List[State], List[State]) =
    IPVersion(s).flatMap(s.memory.eval(_)) match {
      case Some(value) if value.cts.isEmpty => value.e match {
        case ConstantValue(version) if version == 6 => thenWhat(s, v)
        case ConstantValue(_) => elseWhat(s, v)
        case _ => fork(s, v)
      }
      case Some(_) => fork(s, v)
      case None => elseWhat(s, v)
    }

  private def fork(s: State, v: Boolean): (List[State], List[State]) =
    If(ConstrainRaw(IPVersion, :==:(ConstantValue(6))), thenWhat, elseWhat)(s, v)
}
