import org.change.v2.analysis.z3.Z3Util
import org.scalatest.{FlatSpec, Matchers}

class Z3UtilTests extends FlatSpec with Matchers {

  "The shared Z3 solver" should "isolate consecutive query scopes" in {
    val context = Z3Util.z3Context
    val value = context.mkIntConst("shared-solver-scope-test")
    val one = context.mkInt(1, Z3Util.defaultSort)
    val two = context.mkInt(2, Z3Util.defaultSort)

    Z3Util.withSolver { solver =>
      solver.assertCnstr(context.mkEq(value, one))
      solver.check()
    } shouldBe Some(true)

    Z3Util.withSolver { solver =>
      solver.assertCnstr(context.mkEq(value, one))
      solver.assertCnstr(context.mkEq(value, two))
      solver.check()
    } shouldBe Some(false)

    Z3Util.withSolver { solver =>
      solver.assertCnstr(context.mkEq(value, two))
      solver.check()
    } shouldBe Some(true)
  }
}
