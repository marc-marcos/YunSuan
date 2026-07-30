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

  // Key expansion AES-128
  val w0 = rkey(127, 96)
  val w1 = rkey(95, 64)
  val w2 = rkey(63, 32)
  val w3 = rkey(31, 0)

  def rcon(round: UInt): UInt = {
    MuxLookup(round, 0.U(8.W))(Seq(
      0.U -> 0x01.U(8.W), 1.U -> 0x02.U(8.W),
      2.U -> 0x04.U(8.W), 3.U -> 0x08.U(8.W),
      4.U -> 0x10.U(8.W), 5.U -> 0x20.U(8.W),
      6.U -> 0x40.U(8.W), 7.U -> 0x80.U(8.W),
      8.U -> 0x1B.U(8.W), 9.U -> 0x36.U(8.W)
    ))
  }

  val rot = Cat(w3(7,0), w3(31,8))
  val padded = Cat(0.U(96.W), rot)
  val sb_full = subBytes(padded)
  val sub_rot = sb_full(31, 0)

  val rcon_word = Cat(0.U(24.W), rcon(uimm(3,0) - 1.U))

  val w4 = sub_rot ^ w0 ^ rcon_word
  val w5 = w4 ^ w1
  val w6 = w5 ^ w2
  val w7 = w6 ^ w3

  val kf = Cat(w4, w5, w6, w7)

  out.vd := Mux1H(Seq(
    (op.em || op.ef) -> enark,
    op.dm -> demix,
    op.df -> deark,
    op.kf1 -> kf,
    op.kf2 -> kf
  ))
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
