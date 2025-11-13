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

}
