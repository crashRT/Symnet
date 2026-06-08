import org.change.v2.analysis.expression.concrete.nonprimitive.{Symbol, :+:, :@}
import org.change.v2.analysis.expression.concrete.{ConstantValue, SymbolicValue}
import org.change.v2.analysis.memory.{State, Value, MemorySpace}
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._
import org.scalatest.{Matchers, FlatSpec}

/**
 * Author: Radu Stoenescu
 * Don't be a stranger,  symnetic.7.radustoe@spamgourmet.com
 */
class InstructionTests extends FlatSpec with Matchers {

  "Rewrite" should "push another value on the assignment stack" in {

    val (s,f) = InstructionBlock(
      AssignNamedSymbol("IP", SymbolicValue())

    )(State.bigBang)

    s.head.memory.eval("IP") shouldBe a [Some[_]]
  }

  "Dup" should "make two symbol refer the same value" in {

    val (s,f) = InstructionBlock(List(
      AssignNamedSymbol("IP", ConstantValue(2)),
      AssignNamedSymbol("IP-Clone", Symbol("IP")),
      ConstrainNamedSymbol("IP-Clone", :==:(Symbol("IP")))
    ))(State.bigBang)

    val afterState = s.head

    afterState.memory.eval("IP-Clone") shouldBe a [Some[_]]
    afterState.memory.eval("IP").get.e.id shouldEqual afterState.memory.eval("IP-Clone").get.e.id
  }

  "Assign" should "copy constraints when assigning a direct symbol reference" in {
    val (s,f) = InstructionBlock(List(
      AssignNamedSymbol("IP", SymbolicValue()),
      ConstrainNamedSymbol("IP", :&:(:>=:(ConstantValue(10)), :<=:(ConstantValue(20)))),
      AssignNamedSymbol("IP-Clone", Symbol("IP"))
    ))(State.bigBang)

    val clone = s.head.memory.eval("IP-Clone").get

    clone.e.id shouldEqual s.head.memory.eval("IP").get.e.id
    clone.cts.map(_.toString) should contain ("&(List(>=([Const(10)]), <=([Const(20)])))")
  }

  "Assign" should "copy constraints when assigning a direct raw-field reference" in {
    val (s,f) = InstructionBlock(List(
      AssignRaw(TcpSrc, SymbolicValue()),
      ConstrainRaw(TcpSrc, :&:(:>=:(ConstantValue(1000)), :<=:(ConstantValue(2000)))),
      AssignNamedSymbol("SavedSrcPort", :@(TcpSrc)),
      AssignRaw(TcpDst, Symbol("SavedSrcPort"))
    ))(State.bigBang)

    val saved = s.head.memory.eval("SavedSrcPort").get
    val dst = s.head.memory.eval(TcpDst(s.head).get).get

    saved.cts.map(_.toString) should contain ("&(List(>=([Const(1000)]), <=([Const(2000)])))")
    dst.e.id shouldEqual saved.e.id
    dst.cts.map(_.toString) should contain ("&(List(>=([Const(1000)]), <=([Const(2000)])))")
  }

  "Constrain" should "correctly add another constraint to a symbol" in {
    val rwIP = AssignNamedSymbol("IP", SymbolicValue())

    val m = MemorySpace.clean
    val stateZero = State(m)

    val (s1,f1) = rwIP(stateZero)

    // TODO
  }

  "If" should "branch execution correctly" in {
    val (s,f) = InstructionBlock(List(
      AssignNamedSymbol("IP", ConstantValue(2)),
      If(ConstrainNamedSymbol("IP", :==:(ConstantValue(2))), NoOp, NoOp)
    ))(State.bigBang)

    s should have length (1)
    f should have length (1)
  }

  "If" should "branch execution correctly in case of symbolics" in {
    val (s,f) = InstructionBlock(
      AssignNamedSymbol("IP", SymbolicValue()),
      If(ConstrainNamedSymbol("IP", :==:(ConstantValue(2))),
        InstructionBlock(
          ConstrainNamedSymbol("IP", :==:(ConstantValue(3)))
        ),
        InstructionBlock(
          AllocateSymbol("IP"),
          AssignNamedSymbol("IP", SymbolicValue()),
          ConstrainNamedSymbol("IP", :==:(ConstantValue(2)))
        ))
    )(State.bigBang)

    s should have length (1)
    f should have length (1)
  }

  "Deferrable E" should "pass when applied to the same expression" in {
    val (s,f) = InstructionBlock(List(
      AssignNamedSymbol("A", SymbolicValue()),
      AssignNamedSymbol("B", SymbolicValue()),

      AssignNamedSymbol("S1", :+:(Symbol("A"), Symbol("B"))),
      AssignNamedSymbol("S2", :+:(Symbol("A"), Symbol("B"))),
      ConstrainNamedSymbol("S1", :~:(:==:(Symbol("S2"))))
    ))(State.bigBang)

    s should have length (0)
    f should have length (1)
  }

}
