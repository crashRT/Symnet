package org.change.v2.util

/**
 * Author: Radu Stoenescu
 * Don't be a stranger,  symnetic.7.radustoe@spamgourmet.com
 */
package object regexes {

  val ipv4 = """[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"""
  val ipv4Regex = ipv4.r

  val ipv4Interval = s"$ipv4\\s*-\\s*$ipv4"
  val ipv4IntervalRegexWithGroups = s"($ipv4)\\s*-\\s*($ipv4)".r

  val ipv4netmask = """[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}"""
  val ipv4netmaskRegex = ipv4netmask.r

  // IPv6 in the textual forms the Click grammar can carry: full or
  // compressed hex groups.  Mosaic emits the exploded form because the Click
  // lexer reads `::` as the declaration operator.
  val ipv6 = """[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}"""
  val ipv6Regex = ipv6.r
  val ipv6IntervalRegexWithGroups = s"($ipv6)\\s*-\\s*($ipv6)".r
  val ipv6netmaskRegexWithGroups = s"($ipv6)/([0-9]{1,3})".r

  val number = """\d+"""
  val numberRegex = number.r

  val portInterval = number + "-" + number
  val portIntervalRegex = portInterval.r
  val portIntervalRegexWithGroups = ("(" + number + ")\\s*-\\s*(" + number + ")").r

  val mac =
    """[0-9A-F][0-9A-F][:-][0-9A-F][0-9A-F][:-][0-9A-F][0-9A-F][:-]
      |[0-9A-F][0-9A-F][:-][0-9A-F][0-9A-F][:-][0-9A-F][0-9A-F]""".stripMargin
  val macRegex = mac.r

  val macCisco ="""[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"""
  val macCiscoRegex = macCisco.r
}
