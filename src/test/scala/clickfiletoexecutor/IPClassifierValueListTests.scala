package clickfiletoexecutor

import java.io.{File, PrintWriter}

import org.change.parser.clickfile.ClickToAbstractNetwork
import org.change.v2.abstractnet.click.sefl.IPClassifier
import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.{Intable, State}
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.util.canonicalnames._
import org.change.v2.util.conversion.RepresentationConversion._
import org.scalatest.{FlatSpec, Matchers}

/**
 * Value lists in IPClassifier atoms (`dst net A B C`): one atom whose field
 * may take any of the listed values, translated to a single OR constraint.
 */
class IPClassifierValueListTests extends FlatSpec with Matchers {

  /** Runs `classifier` with its output ports wired to ToDevice elements. */
  private def run(classifier: String, outputs: List[String]): ClickExecutionContext = {
    val sinks = outputs.distinct
    val click =
      s"""src :: FromDevice
         |${sinks.map(s => s"$s :: ToDevice").mkString("\n")}
         |cl :: IPClassifier($classifier)
         |src -> cl
         |${outputs.zipWithIndex.map { case (s, i) => s"cl[$i] -> $s" }.mkString("\n")}
         |""".stripMargin
    val file = File.createTempFile("ipclassifier-value-list", ".click")
    file.deleteOnExit()
    val writer = new PrintWriter(file)
    try writer.write(click) finally writer.close()

    var executor = ClickExecutionContext.fromSingle(
      ClickToAbstractNetwork.buildConfig(file.getAbsolutePath))
    while (!executor.isDone) executor = executor.execute()
    executor
  }

  private def reaching(ctx: ClickExecutionContext, sink: String): List[State] =
    ctx.stuckStates.filter(_.history.head.startsWith(sink))

  /** Whether the state still admits `field == value`. */
  private def admits(state: State, field: Intable, value: Long): Boolean =
    ConstrainRaw(field, :==:(ConstantValue(value)))(state, false)._1.nonEmpty

  private def admitsIp(state: State, field: Intable, ip: String): Boolean =
    admits(state, field, ipToNumber(ip))

  "An IPClassifier value list" should "produce one matching and one non-matching state" in {
    val ctx = run("dst net 10.0.0.0/8 192.168.0.0/16, -", List("hit", "miss"))
    reaching(ctx, "hit") should have length 1
    reaching(ctx, "miss") should have length 1
  }

  it should "create fewer states than one branch per value" in {
    val listed = run("dst net 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12, -", List("hit", "miss"))
    val expanded = run(
      "dst net 10.0.0.0/8, dst net 192.168.0.0/16, dst net 172.16.0.0/12, -",
      List("hit", "hit", "hit", "miss"))

    reaching(listed, "hit") should have length 1
    reaching(expanded, "hit") should have length 3
    val listedTotal = listed.stuckStates.length + listed.failedStates.length
    val expandedTotal = expanded.stuckStates.length + expanded.failedStates.length
    listedTotal should be < expandedTotal
  }

  it should "constrain the matching side to the union and the other side to its complement" in {
    val ctx = run("dst net 10.0.0.0/8 192.168.0.0/16, -", List("hit", "miss"))
    val hit = reaching(ctx, "hit").head
    val miss = reaching(ctx, "miss").head

    admitsIp(hit, IPDst, "10.1.2.3") shouldBe true
    admitsIp(hit, IPDst, "192.168.5.5") shouldBe true
    admitsIp(hit, IPDst, "172.16.0.1") shouldBe false

    admitsIp(miss, IPDst, "10.1.2.3") shouldBe false
    admitsIp(miss, IPDst, "192.168.5.5") shouldBe false
    admitsIp(miss, IPDst, "172.16.0.1") shouldBe true
  }

  it should "accept ranges with and without spaces around the dash" in {
    val ctx = run(
      "src net 172.16.0.10 - 172.16.0.20 172.16.0.30-172.16.0.40 10.0.0.0/24, -",
      List("hit", "miss"))
    val hit = reaching(ctx, "hit").head
    val miss = reaching(ctx, "miss").head

    admitsIp(hit, IPSrc, "172.16.0.15") shouldBe true
    admitsIp(hit, IPSrc, "172.16.0.35") shouldBe true
    admitsIp(hit, IPSrc, "10.0.0.200") shouldBe true
    admitsIp(hit, IPSrc, "172.16.0.25") shouldBe false
    admitsIp(miss, IPSrc, "172.16.0.25") shouldBe true
    admitsIp(miss, IPSrc, "172.16.0.20") shouldBe false
  }

  it should "accept host lists" in {
    val ctx = run("dst host 10.0.0.1 10.0.0.3, -", List("hit", "miss"))
    val hit = reaching(ctx, "hit").head
    admitsIp(hit, IPDst, "10.0.0.1") shouldBe true
    admitsIp(hit, IPDst, "10.0.0.3") shouldBe true
    admitsIp(hit, IPDst, "10.0.0.2") shouldBe false
  }

  it should "accept port lists combined with other terms" in {
    val ctx = run("tcp and dst tcp port 135 139 445 and src udp port 53 1053, -", List("hit", "miss"))
    reaching(ctx, "hit") should have length 1
    val hit = reaching(ctx, "hit").head
    admits(hit, TcpDst, 139) shouldBe true
    admits(hit, TcpDst, 445) shouldBe true
    admits(hit, TcpDst, 136) shouldBe false
    admits(hit, TcpSrc, 1053) shouldBe true
    admits(hit, TcpSrc, 54) shouldBe false
    // Not matched: not TCP, or TCP with a port outside a list.
    reaching(ctx, "miss") should have length 3
  }

  it should "keep the single-value meaning, including the mask form" in {
    IPClassifier.valueListConstraint("cl", "dst net 10.0.0.0/8") shouldBe None
    IPClassifier.valueListConstraint("cl", "dst net 10.0.0.0 mask 255.0.0.0") shouldBe None
    IPClassifier.valueListConstraint("cl", "dst tcp port 22") shouldBe None
    IPClassifier.valueListConstraint("cl", "tcp") shouldBe None

    val ctx = run("dst net 10.0.0.0 mask 255.0.0.0, -", List("hit", "miss"))
    val hit = reaching(ctx, "hit").head
    admitsIp(hit, IPDst, "10.200.0.1") shouldBe true
    admitsIp(hit, IPDst, "11.0.0.1") shouldBe false
  }

  it should "build one flat OR for vlantag and ether lists" in {
    IPClassifier.valueListConstraint("cl", "vlantag 10 20") shouldBe Some(
      ConstrainRaw(VLANTag, :||:(List(:==:(ConstantValue(10)), :==:(ConstantValue(20))))))
    IPClassifier.valueListConstraint("cl", "ether dst 0011.2233.4455 0011.2233.4466") shouldBe Some(
      ConstrainRaw(EtherDst, :||:(List(
        :==:(ConstantValue(macToNumberCiscoFormat("0011.2233.4455"))),
        :==:(ConstantValue(macToNumberCiscoFormat("0011.2233.4466")))))))
  }

  it should "reject a list with a value it cannot interpret" in {
    val error = intercept[IllegalArgumentException] {
      IPClassifier.valueListConstraint("cl", "dst net 10.0.0.0/8 10.0.0.1")
    }
    error.getMessage should include("cl")
    error.getMessage should include("10.0.0.1")

    an[IllegalArgumentException] should be thrownBy
      IPClassifier.valueListConstraint("cl", "dst tcp port 22 ssh")

    an[IllegalArgumentException] should be thrownBy
      run("dst host 10.0.0.1 foo, -", List("hit", "miss"))
  }
}
