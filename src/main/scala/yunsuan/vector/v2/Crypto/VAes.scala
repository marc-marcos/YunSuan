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
  val out = IO(Output(ValidIO(new Out)))
  val op = in.bits.op
  val state = in.bits.vs3
  val rkey = in.bits.vs2
  val uimm = in.bits.uimm

  // Encryption path

  val ensb = subBytes(state)
  val ensr = shiftRows(ensb)

  val s1_ensr = RegEnable(ensr, in.valid)
  val s1_op = RegEnable(op, in.valid)
  val s1_rkey = RegEnable(rkey, in.valid)
  val s1_state = RegEnable(state, in.valid)


  val enmix = mixColumns(s1_ensr)
  val enark = Mux1H(Seq(
    s1_op.em -> enmix,
    s1_op.ef -> s1_ensr,
  )) ^ s1_rkey

  // Decryption path

  val desr = shiftRowsInv(state)

  val s1_desr = RegEnable(desr, in.valid)

  val desb = subBytesInv(s1_desr)
  val deark = desb ^ s1_rkey
  val demix = mixColumnsInv(deark)

  // Key expansion AES-128

  val w3 = rkey(127, 96)
  val w2 = rkey(95, 64)
  val w1 = rkey(63, 32)
  val w0 = rkey(31, 0)

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

  val sub_rot = subWord(rot)

  val zimm4 = uimm(3, 0)
  val round = Mux(zimm4 === 0.U || zimm4 > 10.U, zimm4 ^ 0x8.U, zimm4)
  val rcon_word = Cat(0.U(24.W), rcon(round - 1.U))

  val s1_sub_rot = RegEnable(sub_rot, in.valid)
  val s1_rcon_word = RegEnable(rcon_word, in.valid)

  val s1_w3 = s1_rkey(127, 96)
  val s1_w2 = s1_rkey(95, 64)
  val s1_w1 = s1_rkey(63, 32)
  val s1_w0 = s1_rkey(31, 0)

  val nw0 = s1_sub_rot ^ s1_w0 ^ s1_rcon_word
  val nw1 = nw0 ^ s1_w1
  val nw2 = nw1 ^ s1_w2
  val nw3 = nw2 ^ s1_w3
  val kf1 = Cat(nw3, nw2, nw1, nw0)

  // Key expansion AES-256

  val crk3 = rkey(127, 96)
  val crk2 = rkey(95, 64)
  val crk1 = rkey(63, 32)
  val crk0 = rkey(31, 0)

  val rkb3 = state(127, 96)
  val rkb2 = state(95, 64)
  val rkb1 = state(63, 32)
  val rkb0 = state(31, 0)

  val sub_2 = subWord(crk3)

  val rot_2 = Cat(crk3(7, 0), crk3(31, 8))
  val sub_rot_2 = subWord(rot_2)
  val round_2 = Mux(uimm(3, 0) < 2.U || uimm(3, 0) > 14.U, uimm(3, 0) ^ 0x8.U, uimm(3, 0));
  val rcon_2 = Cat(0.U(24.W), rcon((round_2 >> 1) - 1.U))

  val s1_sub_2 = RegEnable(sub_2, in.valid)
  val s1_sub_rot_2 = RegEnable(sub_rot_2, in.valid)
  val s1_rcon_2 = RegEnable(rcon_2, in.valid)
  val s1_rkb0 = RegEnable(rkb0, in.valid)
  val s1_rkb1 = RegEnable(rkb1, in.valid)
  val s1_rkb2 = RegEnable(rkb2, in.valid)
  val s1_rkb3 = RegEnable(rkb3, in.valid)
  val s1_round_2_lsb = RegEnable(round_2(0), in.valid)

  val nw0_odd = s1_sub_2 ^ s1_rkb0
  val nw0_even = s1_sub_rot_2 ^ s1_rcon_2 ^ s1_rkb0
  val nw0_2 = Mux(s1_round_2_lsb === 0.U, nw0_even, nw0_odd)
  val nw1_2 = nw0_2 ^ s1_rkb1
  val nw2_2 = nw1_2 ^ s1_rkb2
  val nw3_2 = nw2_2 ^ s1_rkb3

  val kf2 = Cat(nw3_2, nw2_2, nw1_2, nw0_2)

  val s1_valid = RegNext(in.valid, false.B)
  val s2_valid = RegNext(s1_valid, false.B)

  val s2_enark = RegEnable(enark, s1_valid)
  val s2_demix = RegEnable(demix, s1_valid)
  val s2_deark = RegEnable(deark, s1_valid)
  val s2_kf1 = RegEnable(kf1, s1_valid)
  val s2_kf2 = RegEnable(kf2, s1_valid)
  val s2_zeroResult = RegEnable(s1_state ^ s1_rkey, s1_valid)
  val s2_op = RegEnable(s1_op, s1_valid)

  out.bits.vd := Mux1H(Seq(
    (s2_op.em || s2_op.ef) -> s2_enark,
    s2_op.dm -> s2_demix,
    s2_op.df -> s2_deark,
    s2_op.kf1 -> s2_kf1,
    s2_op.kf2 -> s2_kf2,
    s2_op.zero -> s2_zeroResult
  ))
  out.valid := s2_valid
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
    val em, ef, dm, df, kf1, kf2, zero = Bool()
  }
}
