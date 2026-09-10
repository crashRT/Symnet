package org.change.v2.abstractnet.click.sefl

import org.change.v2.abstractnet.generic.{ConfigParameter, ElementBuilder, GenericElement, Port}
import org.change.v2.analysis.expression.concrete.{ConstantValue, SymbolicValue}
import org.change.v2.analysis.expression.concrete.nonprimitive.Symbol
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.analysis.processingmodels.{Instruction, LocationId}
import org.change.v2.util.conversion.RepresentationConversion._
import org.change.v2.util.regexes._

/**
 * Assigns arbitrary named symbols, then forwards the packet unchanged.
 *
 * `Paint` can only write COLOR and ANNO.  This element generalises it so that
 * a model can seed any named symbol, which is what state living outside the
 * packet header is made of.  An `IPRewriter` mapping, for instance, is ten
 * named symbols per rule.  Seeding them lets a run that starts on the reply
 * side assume a mapping a forward run would have installed, without needing
 * the forward flow in the same run.
 *
 * Each config parameter is one assignment, written `<symbol> <value>...`:
 *
 *   SetNamedSymbol(nat-1-check-sa 8.8.8.8,
 *                  nat-1-check-da 211.14.212.249-211.14.212.254,
 *                  nat-1-check-dp 60000-65535,
 *                  nat-1-apply-da 10.57.0.0/18,
 *                  nat-1-apply-dp any,
 *                  nat-1-apply-fwport 3)
 *
 * A value is a plain number, an IPv4 address, an IPv4 range, an IPv4 CIDR, a
 * numeric range, `any`, or the name of another symbol.  A value with no width
 * becomes a `ConstantValue`; anything wider becomes a `SymbolicValue`
 * constrained to that interval, and `any` an unconstrained one.  Several
 * space-separated values are OR-ed, which is how a prefix that is a list of
 * CIDRs is expressed.
 *
 * Naming another symbol aliases it rather than drawing a second value from the
 * same range.  That distinction matters: a reply's source address is *the*
 * address the mapping matched, not merely one from the same range, and only an
 * alias keeps the two equal.  A referenced symbol has to be assigned earlier in
 * the same config, since assignments run in declaration order.
 *
 * The ANTLR config grammar joins tokens with single spaces, so
 * `1.2.3.4-5.6.7.8` arrives here as `1.2.3.4 - 5.6.7.8`.  Spacing around
 * interval dashes is therefore normalised away before the value is split.
 */
class SetNamedSymbol(name: String,
                     inputPorts: List[Port],
                     outputPorts: List[Port],
                     configParams: List[ConfigParameter])
  extends GenericElement(name,
    "SetNamedSymbol",
    inputPorts,
    outputPorts,
    configParams) {

  import SetNamedSymbol._

  private def assignmentFor(paramValue: String): Instruction = {
    val trimmed = paramValue.trim
    val separator = trimmed.indexOf(' ')
    if (separator < 0)
      throw new IllegalArgumentException(
        s"SetNamedSymbol $name: '$trimmed' is not a '<symbol> <value>' pair")

    val symbol = trimmed.substring(0, separator).trim
    val atoms = atomsOf(trimmed.substring(separator + 1).trim)

    if (atoms.length == 1 && isSymbolReference(atoms.head))
      return AssignNamedSymbol(symbol, Symbol(atoms.head))

    intervalsFor(symbol, atoms) match {
      case Nil =>
        AssignNamedSymbol(symbol, SymbolicValue())
      case (lower, upper) :: Nil if lower == upper =>
        AssignNamedSymbol(symbol, ConstantValue(lower))
      case intervals =>
        InstructionBlock(
          AssignNamedSymbol(symbol, SymbolicValue()),
          ConstrainNamedSymbol(
            symbol,
            intervals.map(rangeConstraint).reduceLeft((left, right) => :|:(left, right))
          )
        )
    }
  }

  /**
   * Split a value into atoms, undoing the spacing the grammar inserts around
   * interval dashes.
   */
  private def atomsOf(value: String): List[String] = value
    .replaceAll("\\s*-\\s*", "-")
    .split("\\s+")
    .filter(_.nonEmpty)
    .toList

  /**
   * Intervals covered by one value list.  An empty list means unconstrained;
   * a single interval with equal bounds means a constant.
   */
  private def intervalsFor(symbol: String, atoms: List[String]): List[(Long, Long)] = {
    if (atoms == List(AnyKeyword)) Nil
    else if (atoms.contains(AnyKeyword))
      throw new IllegalArgumentException(
        s"SetNamedSymbol $name: '$AnyKeyword' cannot be combined with other " +
          s"values for symbol '$symbol'")
    else if (atoms.isEmpty)
      throw new IllegalArgumentException(
        s"SetNamedSymbol $name: symbol '$symbol' has no value")
    else atoms.map(intervalFor(symbol, _))
  }

  private def intervalFor(symbol: String, atom: String): (Long, Long) = atom match {
    case ipv4netmaskRegex() =>
      val parts = atom.split("/")
      ipAndMaskToInterval(parts(0), parts(1))
    case ipv4IntervalRegexWithGroups(start, end) => (ipToNumber(start), ipToNumber(end))
    case ipv4Regex() => (ipToNumber(atom), ipToNumber(atom))
    case portIntervalRegexWithGroups(lower, upper) => (lower.toLong, upper.toLong)
    case numberRegex() => (atom.toLong, atom.toLong)
    case _ =>
      throw new IllegalArgumentException(
        s"SetNamedSymbol $name: unsupported value '$atom' for symbol '$symbol'")
  }

  override def instructions: Map[LocationId, Instruction] = Map(
    inputPortName(0) -> InstructionBlock(
      configParams.map(param => assignmentFor(param.value)) :+ Forward(outputPortName(0))
    )
  )
}

class SetNamedSymbolElementBuilder(name: String)
  extends ElementBuilder(name, "SetNamedSymbol") {

  addInputPort(Port())
  addOutputPort(Port())

  override def buildElement: GenericElement =
    new SetNamedSymbol(name, getInputPorts, getOutputPorts, getConfigParameters)
}

object SetNamedSymbol {

  val AnyKeyword = "any"

  private val symbolNameRegex = """[A-Za-z_][A-Za-z0-9_\-.:@/]*""".r

  /**
   * Anything that is not a literal value but reads like a name refers to
   * another symbol.  Literals are tried first, so `8.8.8.8` is never mistaken
   * for one.
   */
  private def isSymbolReference(atom: String): Boolean =
    atom != AnyKeyword && !isLiteral(atom) && symbolNameRegex.pattern.matcher(atom).matches

  private def isLiteral(atom: String): Boolean = atom match {
    case ipv4netmaskRegex() => true
    case ipv4IntervalRegexWithGroups(_, _) => true
    case ipv4Regex() => true
    case portIntervalRegexWithGroups(_, _) => true
    case numberRegex() => true
    case _ => false
  }

  private def rangeConstraint(interval: (Long, Long)): FloatingConstraint =
    :&:(:>=:(ConstantValue(interval._1)), :<=:(ConstantValue(interval._2)))

  private var unnamedCount = 0

  def getBuilder(name: String): SetNamedSymbolElementBuilder = {
    unnamedCount += 1
    new SetNamedSymbolElementBuilder(name)
  }

  def getBuilder: SetNamedSymbolElementBuilder =
    getBuilder(s"SetNamedSymbol-$unnamedCount")
}
