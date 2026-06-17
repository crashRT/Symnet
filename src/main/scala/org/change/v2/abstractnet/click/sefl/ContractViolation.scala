package org.change.v2.abstractnet.click.sefl

import org.change.v2.abstractnet.generic.{ConfigParameter, ElementBuilder, GenericElement, Port}
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.analysis.processingmodels.{Instruction, LocationId}

class ContractViolation(name: String,
                        elementType: String,
                        inputPorts: List[Port],
                        outputPorts: List[Port],
                        configParams: List[ConfigParameter])
  extends GenericElement(name, elementType, inputPorts, outputPorts, configParams) {

  override def instructions: Map[LocationId, Instruction] = Map(
    inputPortName(0) -> Fail("Contract violation @ " + getName)
  )
}

class ContractViolationElementBuilder(name: String, elementType: String)
  extends ElementBuilder(name, elementType) {

  addInputPort(Port())

  override def buildElement: GenericElement =
    new ContractViolation(name, elementType, getInputPorts, getOutputPorts, getConfigParameters)
}

object ContractViolation {
  private var unnamedCount = 0

  def getBuilder(name: String): ContractViolationElementBuilder = {
    unnamedCount += 1
    new ContractViolationElementBuilder(name, "ContractViolation")
  }

  def getBuilder: ContractViolationElementBuilder =
    getBuilder(s"ContractViolation-$unnamedCount")
}
