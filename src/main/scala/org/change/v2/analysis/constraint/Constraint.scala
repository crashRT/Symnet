package org.change.v2.analysis.constraint

import org.change.v2.analysis.types._
import org.change.v2.analysis.z3.Z3Util
import org.change.v2.interval._
import org.change.v2.interval.IntervalOps._
import z3.scala.{Z3Solver, Z3AST}

trait Constraint {
  /**
   * Materialize a constraint as the set of possible values.
   *
   * An empty list result marks the constraint as unsatisfiable.
   *
   * @param valueType For bound checks.
   */
  def asSet(valueType: NumericType = LongType): List[Interval] = Nil

  /**
   *
   * @param subject On what Z3 AST the constraint applies to.
   * @return The new AST incorporating the current constraint.
   */
  def z3Constrain(subject: Z3AST): Z3AST
}

object Constraint {
  def applyConstraint(s: ValueSet, c: Constraint,
                      t: NumericType = LongType): ValueSet =
    intersect(List(s, c.asSet(t)))

  def applyConstraints(s: ValueSet, cts: List[Constraint],
                       t: NumericType = LongType): ValueSet =
    intersect(s :: cts.map(_.asSet()))
}

object No extends Constraint {
  override def asSet(valueType: NumericType): List[(Long, Long)] = {
    List((valueType.min, valueType.max))
  }

  override def z3Constrain(subject: Z3AST): Z3AST = subject
}

case class LT(v: BigInt) extends Constraint {
  override def asSet(valueType: NumericType): List[(Long, Long)] = {
    List((valueType.min, Z3Util.clampLong(v-1).min(valueType.max)))
  }

  override def z3Constrain(ast: Z3AST): Z3AST =
    Z3Util.z3Context.mkLT(ast, Z3Util.num(v))
}

case class LTE(v: BigInt) extends Constraint {
  override def asSet(valueType: NumericType): List[(Long, Long)] = {
    List((valueType.min, Z3Util.clampLong(v).min(valueType.max)))
  }

  override def z3Constrain(ast: Z3AST): Z3AST =
    Z3Util.z3Context.mkLE(ast, Z3Util.num(v))
}

case class GT(v: BigInt) extends Constraint {
  override def asSet(valueType: NumericType): List[(Long, Long)] = {
    List((Z3Util.clampLong(v+1).max(valueType.min), valueType.max))
  }

  override def z3Constrain(ast: Z3AST): Z3AST =
    Z3Util.z3Context.mkGT(ast, Z3Util.num(v))
}

case class GTE(v: BigInt) extends Constraint{
  override def asSet(valueType: NumericType): List[(Long, Long)] = {
    List((Z3Util.clampLong(v).max(valueType.min), valueType.max))
  }

  override def z3Constrain(ast: Z3AST): Z3AST =
    Z3Util.z3Context.mkGE(ast, Z3Util.num(v))
}

case class E(v: BigInt) extends Constraint{
  override def asSet(valueType: NumericType): List[(Long, Long)] =
    if (valueType.min <= v && v <= valueType.max) List((v.toLong,v.toLong))
    else Nil

  override def z3Constrain(ast: Z3AST): Z3AST =
    Z3Util.z3Context.mkEq(ast, Z3Util.num(v))
}

case class Range(v1: BigInt, v2: BigInt) extends Constraint {
  override def asSet(valueType: NumericType): List[(Long, Long)] = {
    List((Z3Util.clampLong(v1).max(valueType.min), Z3Util.clampLong(v2).min(valueType.max)))
  }

  override def z3Constrain(ast: Z3AST): Z3AST =
    Z3Util.z3Context.mkAnd(
      Z3Util.z3Context.mkGE(ast, Z3Util.num(v1)),
      Z3Util.z3Context.mkLE(ast, Z3Util.num(v2)))
}

case class OR(constraints: List[Constraint]) extends Constraint {
  override def asSet(valueType: NumericType = LongType): List[Interval] =
    union(constraints.map(_.asSet(valueType)))

  override def z3Constrain(subject: Z3AST): Z3AST =
    Z3Util.z3Context.mkOr(constraints.map(_.z3Constrain(subject)):_*)

  override def toString = s"|($constraints)"
}

case class AND(constraints: List[Constraint]) extends Constraint {
  override def asSet(valueType: NumericType = LongType): List[Interval] =
    intersect(constraints.map(_.asSet(valueType)))

  override def z3Constrain(subject: Z3AST): Z3AST =
    Z3Util.z3Context.mkAnd(constraints.map(_.z3Constrain(subject)):_*)
  override def toString = s"&($constraints)"
}

case class NOT(constraint: Constraint) extends Constraint {
  override def asSet(valueType: NumericType = LongType): List[Interval] =
    complement(constraint.asSet(valueType))

  override def z3Constrain(subject: Z3AST): Z3AST =
    Z3Util.z3Context.mkNot(constraint.z3Constrain(subject))
  override def toString = s"~($constraint)"
}

