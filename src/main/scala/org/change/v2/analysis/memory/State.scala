package org.change.v2.analysis.memory

import org.change.v2.analysis.expression.concrete._
import org.change.v2.analysis.memory.TagExp._
import org.change.v2.analysis.processingmodels._
import org.change.v2.analysis.processingmodels.instructions._
import org.change.v2.util.canonicalnames._

import spray.json._

/**
 * Author: Radu Stoenescu
 * Don't be a stranger,  symnetic.7.radustoe@spamgourmet.com
 */
case class State(memory: MemorySpace = MemorySpace.clean,
                 history: List[LocationId] = Nil,
                 errorCause: Option[ErrorCause] = None,
                 instructionHistory: List[Instruction] = Nil,
                 locationStates: Map[LocationId, List[MemorySpace]] = Map.empty) {
  def location: LocationId = history.head
  def forwardTo(locationId: LocationId): State = State(
    memory,
    locationId :: history,
    errorCause,
    instructionHistory,
    locationStates + (locationId -> (memory :: locationStates.getOrElse(locationId, Nil)))
  )
  def status = errorCause.getOrElse("OK")
  def addInstructionToHistory(i: Instruction) = State(memory, history, errorCause, i :: instructionHistory, locationStates)

  def jsonString = {
    import org.change.v2.analysis.memory.jsonformatters.StateToJson._
    this.toJson.toString
  }
  override def toString = jsonString
}

object State {

 def clean = State(MemorySpace.clean)

 def bigBang: State = {
   val bigBang = State(MemorySpace.clean)

   val afterBigBang = InstructionBlock (
     CreateTag("START",0),
     CreateTag("L3", 0),

     Allocate(IPVersion, 4),
     // A constant version lets IfIPVersion6 pick the IPv4 branch without
     // forking.  A symbolic version would also explore "IPv4 layout with
     // version 6", which is not a packet anyone can send.
     Assign(IPVersion, ConstantValue(4)),

     Allocate(Proto, 8),
     Assign(Proto, SymbolicValue()),

     Allocate(IPSrc, 32),
     Assign(IPSrc, SymbolicValue()),
     Constrain(IPSrc, :&:(:>=:(ConstantValue(-2147483648L)), :<=:(ConstantValue(2147483647L)))),
     Allocate(IPDst, 32),
     Assign(IPDst, SymbolicValue()),
     Constrain(IPDst, :&:(:>=:(ConstantValue(-2147483648L)), :<=:(ConstantValue(2147483647L)))),

     Allocate(TTL, 8),
     Assign(TTL, ConstantValue(255)),

     Allocate(IPLength, 16),
     Assign(IPLength, SymbolicValue()),

     Allocate(IPHeaderLength, 4),
     Assign(IPHeaderLength, SymbolicValue()),

     Allocate(HeaderChecksum,16),
     Assign(HeaderChecksum, SymbolicValue()),

     Allocate(IPID, 16),
     Assign(IPID, SymbolicValue()),

     CreateTag("L4", L3Tag + 160),

     Allocate(TcpSrc, 16),
     Assign(TcpSrc, SymbolicValue()),
     Constrain(TcpSrc, :&:(:>=:(ConstantValue(0)), :<=:(ConstantValue(65536)))),

     Allocate(TcpDst, 16),
     Assign(TcpDst, SymbolicValue()),
     Constrain(TcpDst, :&:(:>=:(ConstantValue(0)), :<=:(ConstantValue(65536)))),

     Allocate(TcpSeq, 32),
     Assign(TcpSeq, SymbolicValue()),

     Allocate(TcpAck, 32),
     Assign(TcpAck, SymbolicValue()),

     Allocate(TcpDataOffset, 4),
     Assign(TcpDataOffset, ConstantValue(160)),

     Allocate(TcpReserved,3),
     Assign(TcpReserved,SymbolicValue()),

     Allocate(TcpFlagNS,1),
     Assign(TcpFlagNS,ConstantValue(0)),
     Allocate(TcpFlagCWR,1),
     Assign(TcpFlagCWR,ConstantValue(0)),
     Allocate(TcpFlagECE,1),
     Assign(TcpFlagECE,ConstantValue(0)),
     Allocate(TcpFlagURG,1),
     Assign(TcpFlagURG,ConstantValue(0)),
     Allocate(TcpFlagACK,1),
     Assign(TcpFlagACK,SymbolicValue()),
     Allocate(TcpFlagACK,1),
     Assign(TcpFlagACK,SymbolicValue()),
     Allocate(TcpFlagSYN,1),
     Assign(TcpFlagSYN,SymbolicValue()),
     Allocate(TcpFlagRST,1),
     Assign(TcpFlagRST,ConstantValue(0)),
     Allocate(TcpFlagPSH,1),
     Assign(TcpFlagPSH,ConstantValue(0)),

     //CreateTag("PAYLOAD", :+:(L4Tag,:@(TcpDataOffset)),
     //Allocate(Tag("PAYLOAD"),12000),
     //Assign(Tag("PAYLOAD"),SymbolicValue()),
     CreateTag("END", L4Tag + 12000)
   )(bigBang, true)

   afterBigBang._1.head
 }

 /**
  * Initial state for an IPv6 packet: the IPv6 header at L3 and the same
  * symbolic TCP/UDP ports at L4 as bigBang.  Src/Dst are unsigned 128-bit
  * values (no shift, unlike IPv4).
  */
 def bigBang6: State = {
   val bigBang = State(MemorySpace.clean)
   val maxAddress = (BigInt(1) << 128) - 1

   val afterBigBang = InstructionBlock (
     CreateTag("START",0),
     CreateTag("L3", 0),

     Allocate(IPVersion, 4),
     Assign(IPVersion, ConstantValue(6)),

     Allocate(IP6TrafficClass, 8),
     Assign(IP6TrafficClass, SymbolicValue()),

     Allocate(IP6FlowLabel, 20),
     Assign(IP6FlowLabel, SymbolicValue()),

     Allocate(IP6PayloadLength, 16),
     Assign(IP6PayloadLength, SymbolicValue()),

     Allocate(IP6NextHeader, 8),
     Assign(IP6NextHeader, SymbolicValue()),

     Allocate(IP6HopLimit, 8),
     Assign(IP6HopLimit, ConstantValue(255)),

     Allocate(IP6Src, 128),
     Assign(IP6Src, SymbolicValue()),
     Constrain(IP6Src, :&:(:>=:(ConstantValue(0)), :<=:(ConstantValue(maxAddress)))),
     Allocate(IP6Dst, 128),
     Assign(IP6Dst, SymbolicValue()),
     Constrain(IP6Dst, :&:(:>=:(ConstantValue(0)), :<=:(ConstantValue(maxAddress)))),

     CreateTag("L4", L3Tag + IP6HeaderLength),

     Allocate(TcpSrc, 16),
     Assign(TcpSrc, SymbolicValue()),
     Constrain(TcpSrc, :&:(:>=:(ConstantValue(0)), :<=:(ConstantValue(65536)))),

     Allocate(TcpDst, 16),
     Assign(TcpDst, SymbolicValue()),
     Constrain(TcpDst, :&:(:>=:(ConstantValue(0)), :<=:(ConstantValue(65536)))),

     Allocate(TcpSeq, 32),
     Assign(TcpSeq, SymbolicValue()),

     Allocate(TcpAck, 32),
     Assign(TcpAck, SymbolicValue()),

     Allocate(TcpDataOffset, 4),
     Assign(TcpDataOffset, ConstantValue(160)),

     Allocate(TcpReserved,3),
     Assign(TcpReserved,SymbolicValue()),

     Allocate(TcpFlagNS,1),
     Assign(TcpFlagNS,ConstantValue(0)),
     Allocate(TcpFlagCWR,1),
     Assign(TcpFlagCWR,ConstantValue(0)),
     Allocate(TcpFlagECE,1),
     Assign(TcpFlagECE,ConstantValue(0)),
     Allocate(TcpFlagURG,1),
     Assign(TcpFlagURG,ConstantValue(0)),
     Allocate(TcpFlagACK,1),
     Assign(TcpFlagACK,SymbolicValue()),
     Allocate(TcpFlagACK,1),
     Assign(TcpFlagACK,SymbolicValue()),
     Allocate(TcpFlagSYN,1),
     Assign(TcpFlagSYN,SymbolicValue()),
     Allocate(TcpFlagRST,1),
     Assign(TcpFlagRST,ConstantValue(0)),
     Allocate(TcpFlagPSH,1),
     Assign(TcpFlagPSH,ConstantValue(0)),

     CreateTag("END", L4Tag + 12000)
   )(bigBang, true)

   afterBigBang._1.head
 }
}
