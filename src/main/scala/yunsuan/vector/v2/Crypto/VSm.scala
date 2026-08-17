package yunsuan.vector.v2.Crypto

import _root_.circt.stage._
import chisel3._
import chisel3.util._

class VSm extends Module {
  import VSm._
  import yunsuan.vector.v2.Crypto.Utils.Zvksed._

  val in = IO(Input(ValidIO(new In)))
  val out = IO(Output(ValidIO(new Out)))
  val op = in.bits.op
  val rkey = in.bits.vs2
  val uimm = in.bits.uimm
  val x = in.bits.vs3

  val rk3 = rkey(127, 96)
  val rk2 = rkey(95, 64)
  val rk1 = rkey(63, 32)
  val rk0 = rkey(31, 0)

  val x3 = x(127, 96)
  val x2 = x(95, 64)
  val x1 = x(63, 32)
  val x0 = x(31, 0)

  val B0 = x1 ^ x2 ^ x3 ^ rk0
  val S0 = sm4SubWord(B0)
  val x4 = sm4Round(x0, S0)

  val s1_x1 = RegEnable(x1, in.valid)
  val s1_x2 = RegEnable(x2, in.valid)
  val s1_x3 = RegEnable(x3, in.valid)
  val s1_x4 = RegEnable(x4, in.valid)
  val s1_rk1 = RegEnable(rk1, in.valid)
  val s1_rk2 = RegEnable(rk2, in.valid)
  val s1_rk3 = RegEnable(rk3, in.valid)
  val s1_valid = RegNext(in.valid, false.B)

  val B1 = s1_x2 ^ s1_x3 ^ s1_x4 ^ s1_rk1
  val S1 = sm4SubWord(B1)
  val x5 = sm4Round(s1_x1, S1)

  val s2_x2 = RegEnable(s1_x2, s1_valid)
  val s2_x3 = RegEnable(s1_x3, s1_valid)
  val s2_x4 = RegEnable(s1_x4, s1_valid)
  val s2_x5 = RegEnable(x5, s1_valid)
  val s2_rk2 = RegEnable(s1_rk2, s1_valid)
  val s2_rk3 = RegEnable(s1_rk3, s1_valid)
  val s2_valid = RegNext(s1_valid, false.B)

  val B2 = s2_x3 ^ s2_x4 ^ s2_x5 ^ s2_rk2
  val S2 = sm4SubWord(B2)
  val x6 = sm4Round(s2_x2, S2)

  val s3_x3 = RegEnable(s2_x3, s2_valid)
  val s3_x4 = RegEnable(s2_x4, s2_valid)
  val s3_x5 = RegEnable(s2_x5, s2_valid)
  val s3_x6 = RegEnable(x6, s2_valid)
  val s3_rk2 = RegEnable(s2_rk2, s2_valid)
  val s3_rk3 = RegEnable(s2_rk3, s2_valid)
  val s3_valid = RegNext(s2_valid, false.B)

  val B3 = s3_x4 ^ s3_x5 ^ s3_x6 ^ s3_rk3
  val S3 = sm4SubWord(B3)
  val x7 = sm4Round(s3_x3, S3)

  val roundResult = Cat(x7, s3_x6, s3_x5, s3_x4)

  // vsm4k

  val B0k = rk1 ^ rk2 ^ rk3 ^ ck(4.U*uimm)
  val S0k = sm4SubWord(B0k)
  val rk4 = sm4RoundKey(rk0, S0k)

  val s1_rk4 = RegEnable(rk4, in.valid)
  val roundUimmReg = RegEnable(uimm, in.valid)

  val B1k = s1_rk2 ^ s1_rk3 ^ s1_rk4 ^ ck(4.U*roundUimmReg+1.U)
  val S1k = sm4SubWord(B1k)
  val rk5 = sm4RoundKey(s1_rk1, S1k)

  val s2_rk4 = RegEnable(s1_rk4, s1_valid)
  val s2_rk5 = RegEnable(rk5, s1_valid)
  val round2UimmReg = RegEnable(roundUimmReg, s1_valid)

  val B2k = s2_rk3 ^ s2_rk4 ^ s2_rk5 ^ ck(4.U*round2UimmReg+2.U)
  val S2k = sm4SubWord(B2k)
  val rk6 = sm4RoundKey(s2_rk2, S2k)

  val s3_rk4 = RegEnable(s2_rk4, s2_valid)
  val s3_rk5 = RegEnable(s2_rk5, s2_valid)
  val s3_rk6 = RegEnable(rk6, s2_valid)
  val round3UimmReg = RegEnable(round2UimmReg, s2_valid)

  val B3k = s3_rk4 ^ s3_rk5 ^ s3_rk6 ^ ck(4.U*round3UimmReg+3.U)
  val S3k = sm4SubWord(B3k)
  val rk7 = sm4RoundKey(s3_rk3, S3k)

  val expansionResult = Cat(rk7, s3_rk6, s3_rk5, s3_rk4)

  val s1_op = RegEnable(op, in.valid)
  val s2_op = RegEnable(s1_op, s1_valid)
  val s3_op = RegEnable(s2_op, s2_valid)

  val resultReg = RegEnable(Mux1H(Seq(
    s3_op.round -> roundResult,
    s3_op.keyexpansion -> expansionResult
  )), s3_valid)

  out.bits.vd := resultReg
  out.valid := RegNext(s3_valid, false.B)
}

object VSm {
  def main(args: Array[String]): Unit = {
    println("Generating the VSm hardware")

    val firtoolOpts = Array(
      "--target=systemverilog",
      "-O=release",
      "--disable-annotation-unknown",
      "--lowering-options=explicitBitcast,disallowLocalVariables,disallowPortDeclSharing,locationInfoStyle=none"
    )
    val firtoolAnno = firtoolOpts.map(FirtoolOption.apply).toSeq

    (new ChiselStage).execute(
      Array("--target-dir", "build/vector") ++ args,
      chisel3.stage.ChiselGeneratorAnnotation(() => new VSm()) +: firtoolAnno
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
    val round, keyexpansion = Bool()
  }
}
