package org.change.v2.abstractnet.click

/**
 * radu
 * 3/6/14
 */

import org.change.symbolicexec.blocks.click.IPFilterBlock
import org.change.v2.abstractnet.generic.{ConfigParameter, ElementBuilder, GenericElement, Port}
import org.change.v2.analysis.processingmodels._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.expression.concrete.nonprimitive._
import org.change.v2.analysis.processingmodels.LocationId
import org.change.v2.analysis.expression.concrete._
import org.change.v2.util.canonicalnames._
import org.change.v2.util.conversion.RepresentationConversion._
import org.change.v2.util.conversion.NumberFor
import org.change.v2.util.regexes._

class IPFilter(name: String,
                 inputPorts: List[Port],
                 outputPorts: List[Port],
                 configParams: List[ConfigParameter])
  extends GenericElement(name,
    "IPFilter",
    inputPorts,
    outputPorts,
    configParams) {

  lazy val haskellParam = " [\"" + configParams.map(_.value).mkString("\", \"") + "\"]\n"

  override def outputPortName(which: Int): String = s"$name-out-$which"

  private def conditionToConstraint(condition: String): Instruction = condition match{
    case IPFilter.tcp() => ConstrainRaw(Proto, :==:(ConstantValue(TCPProto)))
    case IPFilter.udp() => ConstrainRaw(Proto, :==:(ConstantValue(UDPProto)))
    case IPFilter.icmp() => ConstrainRaw(Proto, :==:(ConstantValue(ICMPProto)))

    case IPFilter.srcHost(ip) => ConstrainRaw(IPSrc, :==:(ConstantValue(ipToNumber(ip))))
    case IPFilter.dstHost(ip) => ConstrainRaw(IPDst, :==:(ConstantValue(ipToNumber(ip))))
    case IPFilter.srcNet(ip, mask) => {
      val (lower, upper) = ipAndMaskToInterval(ip, mask)
      ConstrainRaw(IPSrc, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper))))
    }
    case IPFilter.dstNet(ip, mask) => {
      val (lower, upper) = ipAndMaskToInterval(ip, mask)
      ConstrainRaw(IPDst, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper))))
    }
    case IPFilter.srcPort(port) => ConstrainRaw(TcpSrc, :==:(ConstantValue(port.toInt)))
    case IPFilter.dstPort(port) => ConstrainRaw(TcpDst, :==:(ConstantValue(port.toInt)))
    case IPFilter.srcPortRange(lower, upper) => ConstrainRaw(TcpSrc,
      :&:(:>=:(ConstantValue(lower.toInt)), :<=:(ConstantValue(upper.toInt))))
    case IPFilter.dstPortRange(lower, upper) => ConstrainRaw(TcpDst,
      :&:(:>=:(ConstantValue(lower.toInt)), :<=:(ConstantValue(upper.toInt))))
  }


  def paramsToInstructions(params: List[String]): Instruction = params match{
    // config example: deny src 192.168.127.0/24 && dst 192.168.180.0/22, allow ip
    case (param :: rest) => {
      val (isAllow, conditions) = param.split("\\s+", 2) match {
        case Array("allow", rest) => (true, rest.split(IPFilter.conditionSeparator).toList)
        case Array("deny", rest) => (false, rest.split(IPFilter.conditionSeparator).toList)
        case _ => (true, param.split(IPFilter.conditionSeparator).toList) // デフォルト
      }

      def conditionsToInstruction(
        isAllow: Boolean, conditions: List[String], rest: List[String]): Instruction = {
        val cond = conditions.head
        cond match {
          case IPFilter.any() =>
            if (isAllow){
              Forward(outputPortName(0))
            } else {
              Fail(s"IPFilter $name: denied by rule $cond")
            }
          case _ =>
            If(conditionToConstraint(cond),
              // then branch (if condition is met)
              if (conditions.length == 1)
                if (isAllow){
                  Forward(outputPortName(0))
                } else {
                  Fail(s"IPFilter $name: denied by rule $cond")
                }
              else
                conditionsToInstruction(isAllow, conditions.tail, rest),
              // else branch,
              if (rest.nonEmpty)
                paramsToInstructions(rest)
              else
                Fail("implicit deny")
            )
          }
      }

      conditionsToInstruction(isAllow, conditions, rest)

    }
    case Nil => Fail("implicit deny")
  }

  override def instructions: Map[LocationId, Instruction] = {
    // Build rule chain from bottom up (implicit deny -> last rule -> ... -> first rule)
    Map(inputPortName(0) -> paramsToInstructions(configParams.map(_.value)))
  }

}

class IPFilterElementBuilder(name: String)
  extends ElementBuilder(name, "IPFilter") {

  override def buildElement: IPFilter = {
    // IPFilter has 1 input port and 1 output port (permit path)
    addInputPort(Port())
    addOutputPort(Port())

    new IPFilter(name, getInputPorts, getOutputPorts, getConfigParameters)
  }
}

object IPFilter {
  val conditionSeparator = """\s+(and|&&)\s+"""

  val tcp = "tcp".r
  val udp = "udp".r
  val icmp = "icmp".r

  val srcHost = ("src (" + ipv4 + ")").r
  val dstHost = ("dst (" + ipv4 + ")").r

  val srcNet = ("src (" + ipv4 + ")/("+ number +")").r
  val dstNet = ("dst (" + ipv4 + ")/("+ number +")").r

  val srcPort = ("src port ("+ number +")").r
  val dstPort = ("dst port ("+ number +")").r

  val srcPortRange = ("src port ("+ number + """)\s*-\s*("""+ number +")").r
  val dstPortRange = ("dst port ("+ number + """)\s*-\s*("""+ number +")").r
  val any = """ip|any""".r

  private var unnamedCount = 0

  private val genericElementName = "ipFilter"

  private def increment {
    unnamedCount += 1
  }

  def getBuilder(name: String): IPFilterElementBuilder = {
    increment ; new IPFilterElementBuilder(name)
  }

  def getBuilder: IPFilterElementBuilder =
    getBuilder(s"$genericElementName-$unnamedCount")

  def quickBuild(name: String, config: String) = IPFilter.getBuilder(name).handleConfigParameter(config).buildElement
}

