package org.change.v2.runners.experiments

import org.change.parser.clickfile.ClickToAbstractNetwork
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.executor.clickabstractnetwork.executionlogging.JsonLogger

/**
 * A generic Click runner for Mosaic integration.
 *
 * Usage: sbt "runMain org.change.v2.runners.experiments.ClickRunner <click_file> [<input_port>]"
 *
 * Outputs JSON to stdout:
 *   Successful: {
 *     <state_json>
 *     ...
 *   }
 *   Failed: {
 *     <state_json>
 *     ...
 *   }
 */
object ClickRunner {

  def main(args: Array[String]): Unit = {
    if (args.isEmpty) {
      System.err.println("Usage: ClickRunner <click_file> [<input_port>]")
      sys.exit(1)
    }

    val clickFile = args(0)

    System.err.println(s"[ClickRunner] Loading: $clickFile")
    val absNet = ClickToAbstractNetwork.buildConfig(clickFile)

    val baseCtx = ClickExecutionContext.fromSingle(absNet).setLogger(JsonLogger)

    // If an input_port argument is given, override the entry location.
    // SymNet's entryLocationId is determined by the Click config; the port
    // argument is informational for now (the config already encodes the start).
    val executor = baseCtx

    System.err.println("[ClickRunner] Starting symbolic execution...")
    val done = executor.untilDone(verbose = false)
    System.err.println(
      s"[ClickRunner] Done. successful=${done.stuckStates.size} failed=${done.failedStates.size}"
    )

    val out = System.out
    out.println(
      done.stuckStates.map(_.jsonString).mkString("Successful: {\n", "\n", "}\n") +
        done.failedStates.map(_.jsonString).mkString("Failed: {\n", "\n", "}\n")
    )
    out.flush()
  }
}
