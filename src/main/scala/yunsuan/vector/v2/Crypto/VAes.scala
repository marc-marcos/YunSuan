package yunsuan.vector.v2.Crypto

import _root_.circt.stage._
import chisel3._
import chisel3.experimental.SourceInfo
import chisel3.util._
import yunsuan.vector.Common._
import yunsuan.vector.v2.Crypto.Utils.Zvkned.subBytes

import scala.collection.immutable.SeqMap
import scala.language.implicitConversions


class VAes extends Module {
  import VAes._
  import yunsuan.vector.v2.Crypto.Utils.Zvkned._

  val in = IO(Input(ValidIO(new In)))
  val out = IO(Output(new Out))
  val op = in.op
  val state = in.vs3
  val rkey = in.vs2
  val uimm = in.uimm
  val ensb = subBytes(state)
  val ensr = shiftRows(ensb)
  val enmix = mixColumns(ensr)
  val enark = Mux1H(Seq(
    op.em -> enmix,
    op.ef -> ensr,
  )) ^ rkey

  val desr = shiftRowsInv(state)
  val desb = subBytesInv(desr)
  val deark = desb ^ rkey
  val demix = mixColumnsInv(deark)

  val keyFwd = Module(new KeyForward)
  keyFwd.io.state := rkey
  keyFwd.io.round_imm := uimm(3, 0)
  val kfResult = keyFwd.io.kf1
  val kf1 = kfResult
  val kf2 = kfResult

  out.vd := Mux1H(Seq(
    (op.em || op.ef) -> enark,
    op.dm -> demix,
    op.df -> deark,
    op.kf1 -> kf1,
    op.kf2 -> kf2
  ))
}

class KeyForward extends Module {
  import VAes._

  val state = IO(Input(UInt(DLEN.W)))
  val round_imm = IO(Input(UInt(4.W)))
  val kf1 = IO(Output(UInt(DLEN.W)))

  val w0 = state(DLEN - 1, DLEN - DLEN/4)
  val w1 = state(DLEN - DLEN/4 - 1, DLEN - DLEN/2)
  val w2 = state(DLEN - DLEN/2 - 1, DLEN - 3*DLEN/4)
  val w3 = state(DLEN - 3*DLEN/4 - 1, 0)

  val w4 = Wire(UInt(32.W))
  val w5 = Wire(UInt(32.W))
  val w6 = Wire(UInt(32.W))
  val w7 = Wire(UInt(32.W))

  def rcon(round: UInt): UInt = {
    MuxLookup(round, 0.U(8.W), Seq(
      0.U -> 0x01.U,
      1.U -> 0x02.U,
      2.U -> 0x04.U,
      3.U -> 0x08.U,
      4.U -> 0x10.U,
      5.U -> 0x20.U,
      6.U -> 0x40.U,
      7.U -> 0x80.U,
      8.U -> 0x1B.U,
      9.U -> 0x36.U
    ))
  }

  val rot = Cat(w3(23,0), w3(31,24))

  val sub_rot = subBytes(Cat(0.U(96.W), rot))(31,0)

  val rcon_word = Cat(0.U(24.W), rcon(round_imm))

  w4 := sub_rot ^ w0 ^ rcon_word

  w5 := w4 ^ w1
  w6 := w5 ^ w2
  w7 := w6 ^ w3

  kf1 := Cat(w4, w5, w6, w7)
}

class SubBytes extends Module {
  import VAes._

  val state = IO(Input(UInt(DLEN.W)))
  val sb = IO(Output(UInt(DLEN.W)))

  sb := subBytes(state)
}

object SubBytes {
  def main(args: Array[String]): Unit = {
    println("Generating the SubBytes hardware")

    val firtoolOpts = Array(
      "--target=systemverilog",
      "-O=release",
      "--disable-annotation-unknown",
      "--lowering-options=explicitBitcast,disallowLocalVariables,disallowPortDeclSharing,locationInfoStyle=none"
    )
    val firtoolAnno = firtoolOpts.map(FirtoolOption.apply).toSeq

    (new ChiselStage).execute(
      Array("--target-dir", "build/vector") ++ args,
      chisel3.stage.ChiselGeneratorAnnotation(() => new SubBytes()) +: firtoolAnno
    )

    println("done")
  }
}

object VAes {
  def main(args: Array[String]): Unit = {
    println("Generating the VAes hardware")

    val firtoolOpts = Array(
      "--target=systemverilog",
      "-O=release",
      "--disable-annotation-unknown",
      "--lowering-options=explicitBitcast,disallowLocalVariables,disallowPortDeclSharing,locationInfoStyle=none"
    )
    val firtoolAnno = firtoolOpts.map(FirtoolOption.apply).toSeq

    (new ChiselStage).execute(
      Array("--target-dir", "build/vector") ++ args,
      chisel3.stage.ChiselGeneratorAnnotation(() => new VAes()) +: firtoolAnno
    )

    println("done")
  }

  val DLEN = 128

  class In extends Bundle {
    val op = new Op
    // round state
    val vs3 = UInt(DLEN.W)
    // round key
    val vs2 = UInt(DLEN.W)
    // round immediate (rnd for key expansion)
    val uimm = UInt(5.W)
  }

  class Out extends Bundle {
    // new round state
    val vd = UInt(DLEN.W)
  }

  class Op extends Bundle {
    val em, ef, dm, df, kf1, kf2 = Bool()
  }
}
