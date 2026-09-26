package org.change.v2.analysis.memory.jsonformatters

import java.io.{BufferedWriter, Closeable, File}
import java.nio.charset.StandardCharsets
import java.nio.file.Files

import org.change.v2.analysis.memory.State
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import spray.json._

case class StreamingExecutionSummary(
  successfulStateCount: Long,
  failedStateCount: Long
)

/**
 * Executes a Click context while spooling finalized states to disk.
 *
 * Active states are explored one at a time as a depth-first worklist.
 * Successful and failed finalized states are serialized as soon as each
 * execution step produces them, then removed before the next step. At the end,
 * the two spool files are copied into the same structured JSON shape produced
 * by ExecutionContextToJson.
 */
object StreamingExecutionContextToJson {

  import org.change.v2.analysis.memory.jsonformatters.StateToJson._

  def executeToFile(
    initialContext: ClickExecutionContext,
    outputFile: File,
    verbose: Boolean = false
  ): StreamingExecutionSummary = {
    val outputParent = Option(outputFile.getAbsoluteFile.getParentFile)
      .getOrElse(new File("."))
    outputParent.mkdirs()

    val successfulSpool = File.createTempFile("symnet-ok-", ".ndjson", outputParent)
    val failedSpool = File.createTempFile("symnet-fail-", ".ndjson", outputParent)
    var successfulWriter: BufferedWriter = null
    var failedWriter: BufferedWriter = null

    try {
      successfulWriter = Files.newBufferedWriter(
        successfulSpool.toPath, StandardCharsets.UTF_8)
      failedWriter = Files.newBufferedWriter(
        failedSpool.toPath, StandardCharsets.UTF_8)

      var successfulCount = 0L
      var failedCount = 0L

      def writeState(writer: BufferedWriter, state: State): Unit = {
        writer.write(state.toJson.compactPrint)
        writer.newLine()
      }

      def drainFinalized(context: ClickExecutionContext): ClickExecutionContext = {
        context.stuckStates.foreach { state =>
          writeState(successfulWriter, state)
          successfulCount += 1
        }
        context.failedStates.foreach { state =>
          writeState(failedWriter, state)
          failedCount += 1
        }
        context.copy(stuckStates = Nil, failedStates = Nil)
      }

      var context = drainFinalized(initialContext)
      while (!context.isDone) {
        val state = context.okStates.head
        val pendingStates = context.okStates.tail
        val stepped = context.copy(okStates = List(state)).execute(verbose)
        context = drainFinalized(
          stepped.copy(okStates = stepped.okStates ++ pendingStates))
      }

      successfulWriter.close()
      successfulWriter = null
      failedWriter.close()
      failedWriter = null

      writeStructuredOutput(
        outputFile,
        successfulSpool,
        failedSpool,
        successfulCount,
        failedCount
      )

      StreamingExecutionSummary(successfulCount, failedCount)
    } finally {
      closeQuietly(successfulWriter)
      closeQuietly(failedWriter)
      successfulSpool.delete()
      failedSpool.delete()
    }
  }

  private def writeStructuredOutput(
    outputFile: File,
    successfulSpool: File,
    failedSpool: File,
    successfulCount: Long,
    failedCount: Long
  ): Unit = {
    val totalCount = successfulCount + failedCount
    val output = Files.newBufferedWriter(outputFile.toPath, StandardCharsets.UTF_8)
    try {
      output.write(
        "{\"total_count\":" + totalCount +
        ",\"explorable\":{\"count\":0,\"states\":[]},")
      output.write(
        "\"finalized\":{\"finalized_count\":" + totalCount +
        ",\"ok\":{\"count\":" + successfulCount + ",\"states\":[")
      copyStates(successfulSpool, output)
      output.write(
        "]},\"fail\":{\"count\":" + failedCount + ",\"states\":[")
      copyStates(failedSpool, output)
      output.write("]}}}")
      output.newLine()
    } finally {
      output.close()
    }
  }

  private def copyStates(spool: File, output: BufferedWriter): Unit = {
    val input = Files.newBufferedReader(spool.toPath, StandardCharsets.UTF_8)
    try {
      var first = true
      var line = input.readLine()
      while (line != null) {
        if (!first) output.write(",")
        output.write(line)
        first = false
        line = input.readLine()
      }
    } finally {
      input.close()
    }
  }

  private def closeQuietly(closeable: Closeable): Unit = {
    if (closeable != null) {
      try closeable.close()
      catch { case _: Exception => () }
    }
  }
}
