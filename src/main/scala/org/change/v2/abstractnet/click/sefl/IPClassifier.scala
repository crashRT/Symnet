package org.change.v2.abstractnet.click.sefl

import org.change.v2.abstractnet.generic.{ConfigParameter, ElementBuilder, GenericElement, Port}
import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.processingmodels._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.analysis.memory.Intable
import org.change.v2.util.canonicalnames._
import org.change.v2.util.conversion.NumberFor
import org.change.v2.util.conversion.RepresentationConversion._
import org.change.v2.util.regexes._

class IPClassifier(name: String,
                    inputPorts: List[Port],
                    outputPorts: List[Port],
                    configParams: List[ConfigParameter])
  extends GenericElement(name,
    "IPClassifier",
    inputPorts,
    outputPorts,
    configParams) {

  val lastIndex = configParams.length - 1


  /**
   * The method takes an atomic tcpdump condition and creates it's associated constraint.
   *
   * Extension to the tcpdump syntax: an atom that takes one value (`src net`,
   * `dst net`, `src host`, `dst host`, `src|dst tcp|udp port`, `vlantag`,
   * `ether src`, `ether dst`) may list several space-separated values, e.g.
   * `dst net 10.0.0.0/8 172.16.0.0/12 192.0.2.10-192.0.2.20`.  The atom then
   * matches when the field equals any of the values, and becomes a single
   * `ConstrainRaw` whose constraint is the OR of the per-value constraints.
   * Because the OR stays inside one header field, it never needs to be split
   * into several branches.  A single value keeps the original meaning.
   *
   * @param condition
   * @return
   */
  private def conditionToConstraint(condition: String): IPClassifier.Atom =
    IPClassifier.valueListConstraint(name, condition) match {
      case Some(atom) => atom
      case None => singleValueConditionToConstraint(condition)
    }

  import IPClassifier.{plain, ipv4Only, ipv6Only}

  private def singleValueConditionToConstraint(condition: String): IPClassifier.Atom = condition match {
    case IPClassifier.color(v) => plain(ConstrainNamedSymbol(Paint.COLOR, :==:(ConstantValue(v.toInt))))

    case IPClassifier.ipProto(v) => plain(ConstrainRaw(IPVersion, :==:(ConstantValue(v.toInt))))

    case IPClassifier.srcHostAddr(ip) => ipv4Only(ConstrainRaw(IPSrc, :==:(ConstantValue(ipToNumber(ip)))))
    case IPClassifier.dstHostAddr(ip) => ipv4Only(ConstrainRaw(IPDst, :==:(ConstantValue(ipToNumber(ip)))))

    case IPClassifier.nexthopAddr(ip) => plain(ConstrainNamedSymbol("nexthop", :==:(ConstantValue(ipToNumber(ip)))))

    case IPClassifier.etherSrc(macSrc) => plain(ConstrainRaw(EtherSrc, :==:(ConstantValue(macToNumberCiscoFormat(macSrc)))))
    case IPClassifier.etherDst(macDst) => plain(ConstrainRaw(EtherDst, :==:(ConstantValue(macToNumberCiscoFormat(macDst)))))

    case IPClassifier.vlanTag(vlanId) => plain(ConstrainRaw(VLANTag, :==:(ConstantValue(vlanId.toInt))))

    case IPClassifier.srcNetRange(startIp, endIp) =>
      ipv4Only(ConstrainRaw(IPSrc, :&:(:>=:(ConstantValue(ipToNumber(startIp))), :<=:(ConstantValue(ipToNumber(endIp))))))
    case IPClassifier.dstNetRange(startIp, endIp) =>
      ipv4Only(ConstrainRaw(IPDst, :&:(:>=:(ConstantValue(ipToNumber(startIp))), :<=:(ConstantValue(ipToNumber(endIp))))))

    case IPClassifier.dstNetAddr(ip, mask) => {
      val (lower, upper) = ipAndMaskToInterval(ip, mask)
      ipv4Only(ConstrainRaw(IPDst, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))))
    }
    case IPClassifier.dstNetExplicitAddr(ip, mask) => {
      val (lower, upper) = ipAndExplicitMaskToInterval(ip, mask)
      ipv4Only(ConstrainRaw(IPDst, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))))
    }
    case IPClassifier.srcNetAddr(ip, mask) => {
      val (lower, upper) = ipAndMaskToInterval(ip, mask)
      ipv4Only(ConstrainRaw(IPSrc, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))))
    }
    case IPClassifier.srcNetExplicitAddr(ip, mask) => {
      val (lower, upper) = ipAndExplicitMaskToInterval(ip, mask)
      ipv4Only(ConstrainRaw(IPSrc, :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))))
    }

    // IPv6 addresses.  The same qualifiers as IPv4; the value decides.
    case IPClassifier.ip6Atom(direction, kind, value) =>
      val field = if (direction == "src") IP6Src else IP6Dst
      val constraint = (if (kind == "host") IPClassifier.ip6HostValueConstraint(value)
        else IPClassifier.ip6NetValueConstraint(value)).getOrElse(throw new IllegalArgumentException(
          s"IPClassifier $name: unsupported IPv6 value '$value' in condition '$condition'"))
      ipv6Only(ConstrainRaw(field, constraint))

    case IPClassifier.srcPort(_, port) => plain(ConstrainRaw(TcpSrc, :==:(ConstantValue(port.toInt))))
    case IPClassifier.dstPort(_, port) => plain(ConstrainRaw(TcpDst, :==:(ConstantValue(port.toInt))))

    case IPClassifier.tcp() => IPClassifier.l4Protocol(TCPProto)
    case IPClassifier.udp() => IPClassifier.l4Protocol(UDPProto)

    case _ => throw new IllegalArgumentException(
      s"IPClassifier $name: unsupported condition '$condition'")
  }

  val portToInstr = scala.collection.mutable.Map[Int, Instruction]()

  /**
   * The construction of instructions from config params works backwards since the i-th
   * if needs the i+1-th if as its the else branch.
   */
  private def buildClassifier(): Unit = for {
    (p,i) <- configParams.zipWithIndex.reverse
  } {
    portToInstr += ((i, paramsToInstructionBlock(p.value,i)))
  }

  override def instructions: Map[LocationId, Instruction] = {
    // Build it first
    if (portToInstr.isEmpty) buildClassifier() else ()
    // Return it later
    Map( inputPortName(0) -> portToInstr(0) )
  }

  def paramsToInstructionBlock(param: String, whichOne: Int): Instruction = param match {
    case IPClassifier.any(_) => Forward(outputPortName(whichOne))

    case IPClassifier.none() => if (whichOne < lastIndex)
//      If the none/false condition is found, then nothing is processed here, the next instruction
//      gets executed instead.
      portToInstr(whichOne + 1)
//      Otherwise, nothing is done here
      else
        Fail(IPClassifier.failErrorMessage)

//      Conversion of tcpdump rules
    case _ => {
      val conditions = param.split(IPClassifier.conditionSeparator).toList

      def conditionsToInstruction(conds: List[String]): Instruction = {
        val cond = conds.head
        conditionToConstraint(cond)(
          // then branch (if condition is met)
          if (conds.length == 1)
            Forward(outputPortName(whichOne))
          else
            conditionsToInstruction(conds.tail),
          // else branch,
          if (whichOne < lastIndex)
            portToInstr(whichOne + 1)
          else
            Fail(IPClassifier.failErrorMessage)
        )
      }

      conditionsToInstruction(conditions)
    }
  }

  override def outputPortName(which: Int): String = s"$getName-out-$which"
}

class IPClassifierElementBuilder(name: String)
  extends ElementBuilder(name, "IPClassifier") {

  addInputPort(Port())

  override def buildElement: GenericElement = {
    new IPClassifier(name, getInputPorts, getOutputPorts, getConfigParameters)
  }
}

object IPClassifier {
  /**
   * One tcpdump atom, given what to do when it matches and when it does not.
   * An atom that reads an address of one IP version only applies to packets
   * of that version; on the other version it simply does not match.
   */
  type Atom = (Instruction, Instruction) => Instruction

  def plain(test: Instruction): Atom = (thenWhat, elseWhat) => If(test, thenWhat, elseWhat)

  def ipv4Only(test: Instruction): Atom = (thenWhat, elseWhat) =>
    IfIPVersion6(elseWhat, If(test, thenWhat, elseWhat))

  def ipv6Only(test: Instruction): Atom = (thenWhat, elseWhat) =>
    IfIPVersion6(If(test, thenWhat, elseWhat), elseWhat)

  /** `tcp` / `udp`: IPv4 Proto or IPv6 Next Header, whichever the packet has. */
  def l4Protocol(proto: Int): Atom = (thenWhat, elseWhat) =>
    IfIPVersion6(
      If(ConstrainRaw(IP6NextHeader, :==:(ConstantValue(proto))), thenWhat, elseWhat),
      If(ConstrainRaw(Proto, :==:(ConstantValue(proto))), thenWhat, elseWhat))

  /** `src|dst host|net <IPv6 value>` (value list handled separately). */
  val ip6Atom = ("""(src|dst) (host|net) (""" + ipv6 + """(?:/[0-9]{1,3})?(?:\s*-\s*""" + ipv6 + """)?)""").r

  def isIPv6Value(value: String): Boolean = value.contains(":")

  def ip6HostValueConstraint(value: String): Option[FloatingConstraint] = value match {
    case ipv6Regex() => Some(:==:(ConstantValue(ipv6ToNumber(value))))
    case _ => None
  }

  def ip6NetValueConstraint(value: String): Option[FloatingConstraint] = value match {
    case ipv6netmaskRegexWithGroups(ip, mask) =>
      val (lower, upper) = ipv6AndMaskToInterval(ip, mask)
      Some(rangeConstraint(lower, upper))
    case ipv6IntervalRegexWithGroups(start, end) =>
      val (lower, upper) = (ipv6ToNumber(start), ipv6ToNumber(end))
      if (upper < lower) throw new IllegalArgumentException(s"IPv6 range end precedes start: $value")
      Some(rangeConstraint(lower, upper))
    case ipv6Regex() => ip6HostValueConstraint(value)
    case _ => None
  }

  // Supported condition formats.
  val conditionSeparator = """\s+(and|&&)\s+"""

  val color = ("paint color (" + number + ")").r

  val ipProto = ("ip proto (" + number + ")").r

  val srcHostAddr = ("src host (" + ipv4 + ")").r
  val srcNetRange = ("src net (" + ipv4 + ")\\s*-\\s*(" + ipv4 + ")").r
  val srcNetAddr = ("src net (" + ipv4 + ")/(" + number + ")").r
  val srcNetExplicitAddr = ("src net (" + ipv4 + ") mask (" + ipv4 + ")").r

  val dstHostAddr = ("dst host (" + ipv4 + ")").r
  val dstNetRange = ("dst net (" + ipv4 + ")\\s*-\\s*(" + ipv4 + ")").r
  val dstNetAddr = ("dst net (" + ipv4 + ")/(" + number + ")").r
  val dstNetExplicitAddr = ("dst net (" + ipv4 + ") mask (" + ipv4 + ")").r

  val nexthopAddr = ("nexthop (" + ipv4 + ")").r

  val srcPort = ("src (tcp|udp) port (" + number + ")").r
  val dstPort = ("dst (tcp|udp) port (" + number + ")").r

  val etherSrc = ("ether src (" + macCisco +")").r
  val etherDst = ("ether dst (" + macCisco +")").r

  val vlanTag = ("vlantag (" + number + ")").r

  /**
   * Qualifier of an atom that accepts a list of values, followed by the values.
   */
  private val valueListAtom =
    """(src net|dst net|src host|dst host|(?:src|dst) (?:tcp|udp) port|vlantag|ether src|ether dst)\s+(.+)""".r

  /**
   * Split a value list into values.  The Click config grammar joins tokens
   * with single spaces, so `1.2.3.4-5.6.7.8` arrives as `1.2.3.4 - 5.6.7.8`;
   * the spacing around interval dashes is removed first (same rule as
   * `SetNamedSymbol`).
   */
  def valuesOf(values: String): List[String] = values
    .replaceAll("\\s*-\\s*", "-")
    .split("\\s+")
    .filter(_.nonEmpty)
    .toList

  private def rangeConstraint(lower: BigInt, upper: BigInt): FloatingConstraint =
    :&:(:>=:(ConstantValue(lower)), :<=:(ConstantValue(upper)))

  private def netValueConstraint(value: String): Option[FloatingConstraint] = value match {
    case ipv4netmaskRegex() =>
      val parts = value.split("/")
      val (lower, upper) = ipAndMaskToInterval(parts(0), parts(1))
      Some(rangeConstraint(lower, upper))
    case ipv4IntervalRegexWithGroups(start, end) =>
      Some(rangeConstraint(ipToNumber(start), ipToNumber(end)))
    case _ => None
  }

  private def hostValueConstraint(value: String): Option[FloatingConstraint] = value match {
    case ipv4Regex() => Some(:==:(ConstantValue(ipToNumber(value))))
    case _ => None
  }

  private def numberValueConstraint(value: String): Option[FloatingConstraint] = value match {
    case numberRegex() => Some(:==:(ConstantValue(value.toLong)))
    case _ => None
  }

  private def macValueConstraint(value: String): Option[FloatingConstraint] = value match {
    case macCiscoRegex() => Some(:==:(ConstantValue(macToNumberCiscoFormat(value))))
    case _ => None
  }

  /**
   * Builds the constraint of an atom carrying two or more values.  Returns
   * `None` when the condition is not a value-list atom (or carries only one
   * value), in which case the single-value rules apply unchanged.  Throws when
   * a value in a list cannot be interpreted.
   */
  def valueListConstraint(elementName: String, condition: String): Option[Atom] =
    condition.trim match {
      case valueListAtom(qualifier, rest) =>
        val values = valuesOf(rest)
        val addressAtom = Set("src net", "dst net", "src host", "dst host").contains(qualifier)
        val ipv6 = addressAtom && values.exists(isIPv6Value)
        if (ipv6 && values.exists(v => !isIPv6Value(v)) && !values.contains("mask"))
          throw new IllegalArgumentException(
            s"IPClassifier $elementName: IPv4 and IPv6 values mixed in condition '$condition'")
        // `src net A mask M` is a single value containing spaces.
        if (values.length < 2 || values.contains("mask")) None
        else {
          val (field, parse): (Intable, String => Option[FloatingConstraint]) = qualifier match {
            case "src net" if ipv6 => (IP6Src, ip6NetValueConstraint)
            case "dst net" if ipv6 => (IP6Dst, ip6NetValueConstraint)
            case "src host" if ipv6 => (IP6Src, ip6HostValueConstraint)
            case "dst host" if ipv6 => (IP6Dst, ip6HostValueConstraint)
            case "src net" => (IPSrc, netValueConstraint)
            case "dst net" => (IPDst, netValueConstraint)
            case "src host" => (IPSrc, hostValueConstraint)
            case "dst host" => (IPDst, hostValueConstraint)
            case "vlantag" => (VLANTag, numberValueConstraint)
            case "ether src" => (EtherSrc, macValueConstraint)
            case "ether dst" => (EtherDst, macValueConstraint)
            case q if q.startsWith("src ") => (TcpSrc, numberValueConstraint)
            case _ => (TcpDst, numberValueConstraint)
          }
          val constraints = values.map { value =>
            parse(value).getOrElse(throw new IllegalArgumentException(
              s"IPClassifier $elementName: unsupported value '$value' in condition '$condition'"))
          }
          val test = ConstrainRaw(field, :||:(constraints))
          Some(if (!addressAtom) plain(test) else if (ipv6) ipv6Only(test) else ipv4Only(test))
        }
      case _ => None
    }

  val tcp = "tcp".r
  val udp = "udp".r

  val any = """\s*(true|\-)\s*""".r
  val none = """\s*false\s*""".r

  val failErrorMessage = "No other alternative output port remaining."

  private var unnamedCount = 0

  private val genericElementName = "IPClassifier"

  private def increment {
    unnamedCount += 1
  }

  def getBuilder(name: String): IPClassifierElementBuilder = {
    increment ; new IPClassifierElementBuilder(name)
  }

  def getBuilder: IPClassifierElementBuilder =
    getBuilder(s"$genericElementName-$unnamedCount")
}