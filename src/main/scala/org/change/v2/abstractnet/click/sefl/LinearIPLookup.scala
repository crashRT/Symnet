package org.change.v2.abstractnet.click.sefl

import org.change.utils.RepresentationConversion
import org.change.v2.abstractnet.generic.{ElementBuilder, GenericElement, ConfigParameter, Port}
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.expression.concrete.nonprimitive._
import org.change.v2.analysis.processingmodels._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

/**
 * A small gift from radu to symnetic.
 */
class LinearIPLookup(name: String,
                     elementType: String,
                     inputPorts: List[Port],
                     outputPorts: List[Port],
                     configParams: List[ConfigParameter])
  extends GenericElement(name,
    elementType,
    inputPorts,
    outputPorts,
    configParams) {

  def paramsToInstructions(params: List[String]): Instruction = params match {
    case (param :: rest) => {
      val (ipmask, port, nexthop) = {
        val split1 = param.split(" ")
        (split1(0), split1(1).toInt, split1(2))
      }

      // デフォルトルートの場合は条件なしで転送
      if (ipmask == "0.0.0.0/0") {
        InstructionBlock(
          Allocate("nexthop"),
          Assign("nexthop", ConstantValue(RepresentationConversion.ipToNumber(nexthop))),
          Forward(outputPortName(port))
        )
      } else {
        val (ip, mask) = {
          val split2 = ipmask.split("/")
          (split2(0), split2(1))
        }

        val (lower, upper) = RepresentationConversion.ipAndMaskToInterval(ip = ip, mask = mask)

        if (nexthop == "onlink") {
          If(Constrain(IPDst, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))),
            InstructionBlock(
              Allocate("nexthop"),
              Assign("nexthop", :@(IPDst)),
              Forward(outputPortName(port))
            ),
            paramsToInstructions(rest)
          )
        } else {
          If(Constrain(IPDst, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))),
            InstructionBlock(
              Allocate("nexthop"),
              Assign("nexthop", ConstantValue(RepresentationConversion.ipToNumber(nexthop))),
              Forward(outputPortName(port))
            ),
            paramsToInstructions(rest)
          )
        }
      }
    }
    case Nil => Fail("No route")
  }

  override def instructions: Map[LocationId, Instruction] = Map(
    inputPortName(0) -> paramsToInstructions(configParams.map(_.value))
  )

  override def outputPortName(which: Int): String = s"$getName-out-$which"
}

class LinearIPLookupElementBuilder(name: String, elementType: String)
  extends ElementBuilder(name, elementType) {

  override def buildElement: GenericElement = {
    new LinearIPLookup(name, elementType, getInputPorts, getOutputPorts, getConfigParameters)
  }
}

object LinearIPLookup {
  private var unnamedCount = 0

  private val genericElementName = "LinearIPLookup"

  private def increment {
    unnamedCount += 1
  }

  def getBuilder(name: String):  LinearIPLookupElementBuilder = {
    increment ; new LinearIPLookupElementBuilder(name, "LinearIPLookup")
  }

  def getBuilder:  LinearIPLookupElementBuilder =
    getBuilder(s"$genericElementName-$unnamedCount")
}