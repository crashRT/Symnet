package org.change.v2.abstractnet.click.sefl

import org.change.v2.abstractnet.generic.{ConfigParameter, ElementBuilder, GenericElement, Port}
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.analysis.processingmodels.{Instruction, LocationId}

class SilentDrop(name: String,
                 elementType: String,
                 inputPorts: List[Port],
                 outputPorts: List[Port],
                 configParams: List[ConfigParameter])
  extends GenericElement(name, elementType, inputPorts, outputPorts, configParams) {

  override def instructions: Map[LocationId, Instruction] = Map(
    inputPortName(0) -> Fail("Endpoint contract drop @ " + getName)
  )
}

class SilentDropElementBuilder(name: String, elementType: String)
  extends ElementBuilder(name, elementType) {

  addInputPort(Port())

  override def buildElement: GenericElement =
    new SilentDrop(name, elementType, getInputPorts, getOutputPorts, getConfigParameters)
}

object SilentDrop {
  private var unnamedCount = 0

  def getBuilder(name: String): SilentDropElementBuilder = {
    unnamedCount += 1
    new SilentDropElementBuilder(name, "SilentDrop")
  }

  def getBuilder: SilentDropElementBuilder =
    getBuilder(s"SilentDrop-$unnamedCount")
}
