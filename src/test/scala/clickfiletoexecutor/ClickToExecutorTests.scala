package clickfiletoexecutor

import org.change.utils.RepresentationConversion
import org.change.parser.clickfile.ClickToAbstractNetwork
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.executor.clickabstractnetwork._
import org.change.v2.util.canonicalnames._
import org.scalatest.{Matchers, FlatSpec}

/**
 * Author: Radu Stoenescu
 * Don't be a stranger,  symnetic.7.radustoe@spamgourmet.com
 */
class ClickToExecutorTests extends FlatSpec with Matchers {

  "A src-dst click" should "generate a valid no op executor" in {
    val absNet = ClickToAbstractNetwork.buildConfig("src/main/resources/click_test_files/SrcDst.click")
    val executor = ClickExecutionContext.fromSingle(absNet)

    executor shouldBe a [ClickExecutionContext]
  }

  "A src-dst click executor" should "propagate the bing-bang state to dst, becoming stuck" in {
    val absNet = ClickToAbstractNetwork.buildConfig("src/main/resources/click_test_files/SrcDst.click")
    val executor = ClickExecutionContext.fromSingle(absNet)

    var crtExecutor = executor
    while(! crtExecutor.isDone) {
      crtExecutor = crtExecutor.execute()
    }

    crtExecutor.stuckStates should have length (1)
    crtExecutor.stuckStates.head.history should have length (4)
  }

  "A src-paint-dst executor" should "correctly paint the bloody flow" in {
    val absNet = ClickToAbstractNetwork.buildConfig("src/main/resources/click_test_files/SrcPaintDst.click")
    val executor = ClickExecutionContext.fromSingle(absNet)

    var crtExecutor = executor
    while(! crtExecutor.isDone) {
      crtExecutor = crtExecutor.execute()
    }

    crtExecutor.stuckStates should have length (1)
    crtExecutor.stuckStates.head.history should have length (6)
    crtExecutor.stuckStates.head.memory.eval("COLOR").get.e should be (ConstantValue(10))
  }

  "A src-classif-dst click" should "generate a valid executor" in {
    val absNet = ClickToAbstractNetwork.buildConfig("src/main/resources/click_test_files/Classif.click")
    val executor = ClickExecutionContext.fromSingle(absNet)

    executor shouldBe a [ClickExecutionContext]
  }

  "Loop detection" should "include constant assignments in IP packet-space comparison" in {
    val targetIp = RepresentationConversion.ipToNumber("10.0.0.1")
    val otherIp = RepresentationConversion.ipToNumber("10.0.0.2")

    val oldState = InstructionBlock(
      Constrain(IPDst, :==:(ConstantValue(targetIp)))
    )(State.bigBang, true)._1.head
    val oldMem = oldState.memory
    val ipDstOffset = IPDst(oldState).get
    val sameConstantNewMem = oldMem.Assign(ipDstOffset, ConstantValue(targetIp)).get
    val differentConstantNewMem = oldMem.Assign(ipDstOffset, ConstantValue(otherIp)).get

    ClickExecutionContext.isIpForwardingLoop(oldMem, sameConstantNewMem) should be (true)
    ClickExecutionContext.isIpForwardingLoop(oldMem, differentConstantNewMem) should be (false)
  }

}
