package org.change.v2.util.conversion

object RepresentationConversion {

  // 2^31を定義
  private val IP_OFFSET = 2147483648L

  def ipToNumber(ip: String): Long = {
    val unsigned = ip.split("\\.").map(Integer.parseInt(_)).foldLeft(0L)((a:Long, g:Int)=> a * 256 + g)
    // 符号付き整数の範囲に変換: IP値 - 2^31
    unsigned - IP_OFFSET
  }

  def macToNumber(mac: String): Long = {
    mac.toLowerCase.split(":").map(Integer.parseInt(_, 16)).foldLeft(0L)((a:Long, g:Int)=> a * 256 + g)
  }

  /**
   * TODO: Check what is the Cisco format.
   * @param mac
   * @return
   */
  def macToNumberCiscoFormat(mac: String): Long = {
    mac.toLowerCase.split("\\.").map(Integer.parseInt(_, 16)).foldLeft(0L)((a:Long, g:Int)=> a * 65536 + g)
  }

  def ipAndMaskToInterval(ip: String, mask: String): (Long, Long) = {
    // まず符号なしの値で計算
    val unsignedIp = ip.split("\\.").map(Integer.parseInt(_)).foldLeft(0L)((a:Long, g:Int)=> a * 256 + g)
    val maskv = Integer.parseInt(mask)
    val addrS = 32 - maskv
    val lowerM = Long.MaxValue << addrS
    val higherM = Long.MaxValue >>> (maskv + 31)
    val lowerBound = unsignedIp & lowerM
    val upperBound = unsignedIp | higherM
    // 符号付き範囲に変換
    (lowerBound - IP_OFFSET, upperBound - IP_OFFSET)
  }

  def ipAndExplicitMaskToInterval(ip: String, mask: String): (Long, Long) = {
    // まず符号なしの値で計算
    val unsignedIp = ip.split("\\.").map(Integer.parseInt(_)).foldLeft(0L)((a:Long, g:Int)=> a * 256 + g)
    val unsignedMask = mask.split("\\.").map(Integer.parseInt(_)).foldLeft(0L)((a:Long, g:Int)=> a * 256 + g)
    val lowerBound = unsignedIp & unsignedMask
    val upperBound = (((unsignedIp | (~unsignedMask)) << 32) >>> 32)
    // 符号付き範囲に変換
    (lowerBound - IP_OFFSET, upperBound - IP_OFFSET)
  }


  /**
   * IPv6 address as its unsigned 128-bit value.  Unlike IPv4 there is no
   * 2^31 shift: values go to Z3 through mkNumeral, which keeps them exact.
   */
  def ipv6ToNumber(ip: String): BigInt =
    BigInt(1, java.net.InetAddress.getByName(requireIPv6(ip)).getAddress)

  def ipv6AndMaskToInterval(ip: String, mask: String): (BigInt, BigInt) = {
    val len = Integer.parseInt(mask)
    if (len < 0 || len > 128)
      throw new IllegalArgumentException(s"IPv6 prefix length out of range: $ip/$mask")
    val hostBits = (BigInt(1) << (128 - len)) - 1
    val value = ipv6ToNumber(ip)
    val lower = value & ~hostBits & ((BigInt(1) << 128) - 1)
    (lower, lower | hostBits)
  }

  def numberToIPv6(value: BigInt): String = {
    val bytes = value.toByteArray.reverse.padTo(16, 0.toByte).take(16).reverse
    java.net.InetAddress.getByAddress(bytes).getHostAddress
  }

  private def requireIPv6(ip: String): String = {
    if (!ip.contains(":") || ip.exists(c => !(c.isDigit || "abcdefABCDEF:".contains(c))))
      throw new IllegalArgumentException(s"Not an IPv6 address: $ip")
    ip
  }

}
