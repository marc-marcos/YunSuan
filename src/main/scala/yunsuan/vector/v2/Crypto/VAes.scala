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
  val op = in.op
  val state = in.vs3
  val rkey = in.vs2
  val uimm = in.uimm

  // Encryption path

  val ensb = subBytes(state)
  val ensr = shiftRows(ensb)

  val ensr_reg = RegEnable(ensr, in.valid)
  val op_reg = RegEnable(op, in.valid)
  val rkey_reg = RegEnable(rkey, in.valid)


  val enmix = mixColumns(ensr_reg)
  val enark = Mux1H(Seq(
    op_reg.em -> enmix,
    op_reg.ef -> ensr_reg,
  )) ^ rkey_reg

  // Decryption path

  val desr = shiftRowsInv(state)

  val desr_reg = RegEnable(desr, in.valid)

  val desb = subBytesInv(desr_reg)
  val deark = desb ^ rkey_reg
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

  val sub_rot_reg = RegEnable(sub_rot, in.valid)
  val rcon_word_reg = RegEnable(rcon_word, in.valid)

  val w3_reg = rkey_reg(127, 96)
  val w2_reg = rkey_reg(95, 64)
  val w1_reg = rkey_reg(63, 32)
  val w0_reg = rkey_reg(31, 0)

  val nw0 = sub_rot_reg ^ w0_reg ^ rcon_word_reg
  val nw1 = nw0 ^ w1_reg
  val nw2 = nw1 ^ w2_reg
  val nw3 = nw2 ^ w3_reg
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

  val sub_2_reg = RegEnable(sub_2, in.valid)
  val sub_rot_2_reg = RegEnable(sub_rot_2, in.valid)
  val rcon_2_reg = RegEnable(rcon_2, in.valid)
  val rkb0_reg = RegEnable(rkb0, in.valid)
  val rkb1_reg = RegEnable(rkb1, in.valid)
  val rkb2_reg = RegEnable(rkb2, in.valid)
  val rkb3_reg = RegEnable(rkb3, in.valid)
  val round_2_lsb_reg = RegEnable(round_2(0), in.valid)


  val nw0_odd = sub_2_reg ^ rkb0_reg
  val nw0_even = sub_rot_2_reg ^ rcon_2_reg ^ rkb0_reg
  val nw0_2 = Mux(round_2_lsb_reg === 0.U, nw0_even, nw0_odd)
  val nw1_2 = nw0_2 ^ rkb1_reg
  val nw2_2 = nw1_2 ^ rkb2_reg
  val nw3_2 = nw2_2 ^ rkb3_reg

  val kf2 = Cat(nw3_2, nw2_2, nw1_2, nw0_2)

  val stage1_valid = RegNext(in.valid, false.B)
  val stage2_valid = RegNext(stage1_valid, false.B)

  val enark_reg = RegEnable(enark, stage1_valid)
  val demix_reg = RegEnable(demix, stage1_valid)
  val deark_reg = RegEnable(deark, stage1_valid)
  val kf1_reg = RegEnable(kf1, stage1_valid)
  val kf2_reg = RegEnable(kf2, stage1_valid)
  val op_stage1 = RegEnable(op_reg, stage1_valid)

  out.bits.vd := Mux1H(Seq(
    (op_stage1.em || op_stage1.ef) -> enark_reg,
    op_stage1.dm -> demix_reg,
    op_stage1.df -> deark_reg,
    op_stage1.kf1 -> kf1_reg,
    op_stage1.kf2 -> kf2_reg
  ))
  out.valid := stage2_valid
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
