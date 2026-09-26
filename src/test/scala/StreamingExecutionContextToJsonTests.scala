import java.nio.charset.StandardCharsets
import java.nio.file.Files

import org.change.v2.analysis.expression.concrete.ConstantValue
import org.change.v2.analysis.memory.State
import org.change.v2.analysis.memory.jsonformatters.StreamingExecutionContextToJson
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.util.canonicalnames.IPDst
import org.scalatest.{FlatSpec, Matchers}
import spray.json._

class StreamingExecutionContextToJsonTests extends FlatSpec with Matchers {

  "Streaming execution" should "write finalized states in the structured JSON format" in {
    val context = ClickExecutionContext(
      instructions = Map(
        "start" -> If(
          Constrain(IPDst, :==:(ConstantValue(0))),
          Forward("finish"),
          Fail("rejected")
        )
      ),
      links = Map.empty,
      okStates = List(State.bigBang.forwardTo("start")),
      failedStates = Nil,
      stuckStates = Nil
    )
    val outputDirectory = Files.createTempDirectory("symnet-streaming-test-")
    val output = outputDirectory.resolve("out.json").toFile

    try {
      val summary = StreamingExecutionContextToJson.executeToFile(
        context, output, verbose = false)
      val json = new String(
        Files.readAllBytes(output.toPath), StandardCharsets.UTF_8
      ).parseJson.asJsObject
      val finalized = json.fields("finalized").asJsObject
      val successful = finalized.fields("ok").asJsObject
      val failed = finalized.fields("fail").asJsObject

      summary.successfulStateCount shouldBe 1
      summary.failedStateCount shouldBe 1
      json.fields("total_count") shouldBe JsNumber(2)
      json.fields("explorable").asJsObject.fields("count") shouldBe JsNumber(0)
      finalized.fields("finalized_count") shouldBe JsNumber(2)
      successful.fields("count") shouldBe JsNumber(1)
      successful.fields("states").asInstanceOf[JsArray].elements should have length 1
      failed.fields("count") shouldBe JsNumber(1)
      failed.fields("states").asInstanceOf[JsArray].elements should have length 1
      outputDirectory.toFile.list().toSeq shouldBe Seq("out.json")
    } finally {
      output.delete()
      outputDirectory.toFile.delete()
    }
  }
}
