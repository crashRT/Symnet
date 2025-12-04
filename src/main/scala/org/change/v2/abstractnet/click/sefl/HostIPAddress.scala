package org.change.v2.abstractnet.click.sefl

import org.change.v2.abstractnet.generic.{ConfigParameter, ElementBuilder, GenericElement, Port}
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.expression.concrete.nonprimitive._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.analysis.processingmodels.{Instruction, LocationId}
import org.change.v2.util.conversion.RepresentationConversion._
import org.change.v2.util.canonicalnames._
import org.change.v2.analysis.memory.TagExp._
import org.change.v2.analysis.memory.Tag
import org.change.v2.util.regexes._

// 送信元であるホストのIPアドレスを条件に追加する
class HostIPAddress(name: String,
                   elementType: String,
                   inputPorts: List[Port],
                   outputPorts: List[Port],
                   configParams: List[ConfigParameter])
  extends GenericElement(name,
    elementType,
    inputPorts,
    outputPorts,
    configParams) {

  override def instructions: Map[LocationId, Instruction] = {
    val address = configParams(0).value
    address match {
      // IPアドレスを指定の場合
      case HostIPAddress.HostAddr(ip) =>
        Map(inputPortName(0) ->
          InstructionBlock(
            Constrain(IPSrc, :==:(ConstantValue(ipToNumber(ip)))),
            Forward(outputPortName(0))
          )
        )
      // IPアドレス帯を指定の場合
      case HostIPAddress.HostNetAddr(ip, mask) =>
        val (lower, upper) = ipAndMaskToInterval(ip, mask)
        Map(inputPortName(0) ->
          InstructionBlock(
            ConstrainRaw(IPSrc, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))),
            Forward(outputPortName(0))
          )
        )
    }
  }
}

class HostIPAddressElementBuilder(name: String, elementType: String)
  extends ElementBuilder(name, elementType) {

  addInputPort(Port())
  addOutputPort(Port())

  override def buildElement: GenericElement = {
    new HostIPAddress(name, elementType, getInputPorts, getOutputPorts, getConfigParameters)
  }
}

object HostIPAddress {

  val HostAddr = ("(" + ipv4 + ")").r
  val HostNetAddr = ("(" + ipv4 + ")/(" + number + ")").r

  private var unnamedCount = 0

  private val genericElementName = "hostipaddress"

  private def increment {
    unnamedCount += 1
  }

  def getBuilder(name: String): HostIPAddressElementBuilder = {
    increment ; new HostIPAddressElementBuilder(name, "HostIPAddress")
  }

  def getBuilder: HostIPAddressElementBuilder =
    getBuilder(s"$genericElementName-$unnamedCount")
}
