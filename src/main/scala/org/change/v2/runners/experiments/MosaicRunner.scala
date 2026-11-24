package org.change.v2.runners.experiments

import java.io.{File, FilenameFilter}
import org.change.parser.clickfile.ClickToAbstractNetwork
import org.change.parser.interclicklinks.InterClickLinksParser
import org.change.v2.analysis.memory.jsonformatters.StreamingExecutionContextToJson
import org.change.v2.analysis.memory.State
import org.change.v2.executor.clickabstractnetwork.ClickExecutionContext

object MosaicRunner {
  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      println("Usage: sbt \"runMain org.change.v2.runners.experiments.MosaicRunner <folder_path> <start_port> [output_file] [ipv4|ipv6]\"")
      sys.exit(1)
    }

    val folderPath = args(0)
    val startPort = args(1)
    val outputPath = if (args.length >= 3) args(2) else "out.json"
    // The injected packet: a symbolic IPv4 packet (default) or IPv6 packet.
    val ipVersion = if (args.length >= 4) args(3) else "ipv4"
    val initialState: State = ipVersion match {
      case "ipv4" => State.bigBang
      case "ipv6" => State.bigBang6
      case other =>
        println(s"Error: unknown IP version '$other' (expected ipv4 or ipv6)")
        sys.exit(1)
    }

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
      startElems = Some(List(startTuple)),
      initialState = initialState
    )

    val outputFile = new File(outputPath)
    val summary = StreamingExecutionContextToJson.executeToFile(
      ctx, outputFile, verbose = true)

    println(
      s"SymNet finalized states: ${summary.successfulStateCount} successful, " +
      s"${summary.failedStateCount} failed")
    println(s"SymNet results written to ${outputFile.getPath}")
  }
}
