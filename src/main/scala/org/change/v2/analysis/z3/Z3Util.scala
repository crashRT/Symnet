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
  lazy val bv32Sort = z3Context.mkBVSort(32)
}
