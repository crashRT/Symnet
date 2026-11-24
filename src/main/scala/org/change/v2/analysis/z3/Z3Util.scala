package org.change.v2.analysis.z3

import z3.scala.{Z3Context, Z3Config, Z3Solver}

/**
 * Author: Radu Stoenescu
 * Don't be a stranger,  symnetic.7.radustoe@spamgourmet.com
 */
object Z3Util {

  lazy val z3Context = new Z3Context(new Z3Config("MODEL" -> true))

  private lazy val intSort = z3Context.mkIntSort()

  private lazy val sharedSolver = z3Context.mkSolver()

  /** Run one isolated query without allocating another retained Z3Solver. */
  def withSolver[A](query: Z3Solver => A): A = sharedSolver.synchronized {
    sharedSolver.push()
    try query(sharedSolver)
    finally sharedSolver.pop()
  }

  lazy val defaultSort = intSort

  /** An exact integer constant of the default sort (no 32-bit truncation). */
  def num(v: BigInt) = z3Context.mkNumeral(v.toString, defaultSort)

  /** Clamp a value to the Long range (for the interval-based `asSet` views). */
  def clampLong(v: BigInt): Long =
    if (v > BigInt(Long.MaxValue)) Long.MaxValue
    else if (v < BigInt(Long.MinValue)) Long.MinValue
    else v.toLong
  lazy val bv32Sort = z3Context.mkBVSort(32)
}
