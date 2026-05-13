package org.change.v2.runners.experiments

import java.io.{File, FilenameFilter}
import org.change.parser.clickfile.ClickToAbstractNetwork
import org.change.parser.interclicklinks.InterClickLinksParser
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext
import org.change.v2.executor.clickabstractnetwork.executionlogging.JsonLogger
import org.change.v2.analysis.memory.State

object MosaicRunner {
  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      println("Usage: sbt \"runMain org.change.v2.runners.experiments.MosaicRunner <folder_path> <start_port>\"")
      sys.exit(1)
    }

    val folderPath = args(0)
    val startPort = args(1)

    val clicksFolder = new File(folderPath)
    if (!clicksFolder.exists() || !clicksFolder.isDirectory) {
      println(s"Error: Directory $folderPath does not exist.")
      sys.exit(1)
    }

    val clicks = clicksFolder.list(new FilenameFilter {
      override def accept(dir: File, name: String): Boolean = name.endsWith(".click")
    }).sorted.map(clicksFolder.getPath + File.separatorChar + _)

    val linksPath = clicksFolder.getPath + File.separatorChar + "links.link"
    val links = if (new File(linksPath).exists()) {
      InterClickLinksParser.parseLinks(linksPath)
    } else {
      Iterable.empty[(String, String, Int, String, String, Int)]
    }

    val startParts = startPort.split(":")
    if (startParts.length != 3) {
      println(s"Error: start_port must be in format 'filename:element:port' (e.g. client_a:uplink_in:0)")
      sys.exit(1)
    }
    val startTuple = (startParts(0), startParts(1), startParts(2).toInt)

    val ctx = ClickExecutionContext.buildAggregated(
      clicks.map(ClickToAbstractNetwork.buildConfig(_, prefixedElements = true)),
      links,
      startElems = Some(List(startTuple))
    ).setLogger(JsonLogger)

    val done = ctx.untilDone(verbose = false)

    val out = System.out
    out.println(
      done.stuckStates.map(_.jsonString).mkString("Successful: {\n", "\n", "}\n") +
      done.failedStates.map(_.jsonString).mkString("Failed: {\n", "\n", "}\n")
    )
    out.flush()
  }
}
