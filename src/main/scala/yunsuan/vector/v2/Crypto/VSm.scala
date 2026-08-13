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

  // The four SM4 rounds are split into four pipeline stages, one round per
  // stage.  The first stage consumes the input accepted in this cycle and
  // the fourth stage produces the result.

  val B0 = x1 ^ x2 ^ x3 ^ rk0
  val S0 = sm4SubWord(B0)
  val x4 = sm4Round(x0, S0)

  val roundX1Reg = RegEnable(x1, in.valid)
  val roundX2Reg = RegEnable(x2, in.valid)
  val roundX3Reg = RegEnable(x3, in.valid)
  val roundX4Reg = RegEnable(x4, in.valid)
  val roundRk1Reg = RegEnable(rk1, in.valid)
  val roundRk2Reg = RegEnable(rk2, in.valid)
  val roundRk3Reg = RegEnable(rk3, in.valid)
  val roundValid = RegNext(in.valid)

  val B1 = roundX2Reg ^ roundX3Reg ^ roundX4Reg ^ roundRk1Reg
  val S1 = sm4SubWord(B1)
  val x5 = sm4Round(roundX1Reg, S1)

  val round2X2Reg = RegEnable(roundX2Reg, roundValid)
  val round2X3Reg = RegEnable(roundX3Reg, roundValid)
  val round2X4Reg = RegEnable(roundX4Reg, roundValid)
  val round2X5Reg = RegEnable(x5, roundValid)
  val round2Rk2Reg = RegEnable(roundRk2Reg, roundValid)
  val round2Rk3Reg = RegEnable(roundRk3Reg, roundValid)
  val round2Valid = RegNext(roundValid)

  val B2 = round2X3Reg ^ round2X4Reg ^ round2X5Reg ^ round2Rk2Reg
  val S2 = sm4SubWord(B2)
  val x6 = sm4Round(round2X2Reg, S2)

  val round3X3Reg = RegEnable(round2X3Reg, round2Valid)
  val round3X4Reg = RegEnable(round2X4Reg, round2Valid)
  val round3X5Reg = RegEnable(round2X5Reg, round2Valid)
  val round3X6Reg = RegEnable(x6, round2Valid)
  val round3Rk2Reg = RegEnable(round2Rk2Reg, round2Valid)
  val round3Rk3Reg = RegEnable(round2Rk3Reg, round2Valid)
  val round3Valid = RegNext(round2Valid)

  val B3 = round3X4Reg ^ round3X5Reg ^ round3X6Reg ^ round3Rk3Reg
  val S3 = sm4SubWord(B3)
  val x7 = sm4Round(round3X3Reg, S3)

  val roundResult = Cat(x7, round3X6Reg, round3X5Reg, round3X4Reg)

  // vsm4k

  val B0k = rk1 ^ rk2 ^ rk3 ^ ck(4.U*uimm)
  val S0k = sm4SubWord(B0k)
  val rk4 = sm4RoundKey(rk0, S0k)

  val roundRk4Reg = RegEnable(rk4, in.valid)
  val roundUimmReg = RegEnable(uimm, in.valid)

  val B1k = roundRk2Reg ^ roundRk3Reg ^ roundRk4Reg ^ ck(4.U*roundUimmReg+1.U)
  val S1k = sm4SubWord(B1k)
  val rk5 = sm4RoundKey(roundRk1Reg, S1k)

  val round2Rk4Reg = RegEnable(roundRk4Reg, roundValid)
  val round2Rk5Reg = RegEnable(rk5, roundValid)
  val round2UimmReg = RegEnable(roundUimmReg, roundValid)

  val B2k = round2Rk3Reg ^ round2Rk4Reg ^ round2Rk5Reg ^ ck(4.U*round2UimmReg+2.U)
  val S2k = sm4SubWord(B2k)
  val rk6 = sm4RoundKey(round2Rk2Reg, S2k)

  val round3Rk4Reg = RegEnable(round2Rk4Reg, round2Valid)
  val round3Rk5Reg = RegEnable(round2Rk5Reg, round2Valid)
  val round3Rk6Reg = RegEnable(rk6, round2Valid)
  val round3UimmReg = RegEnable(round2UimmReg, round2Valid)

  val B3k = round3Rk4Reg ^ round3Rk5Reg ^ round3Rk6Reg ^ ck(4.U*round3UimmReg+3.U)
  val S3k = sm4SubWord(B3k)
  val rk7 = sm4RoundKey(round3Rk3Reg, S3k)

  val expansionResult = Cat(rk7, round3Rk6Reg, round3Rk5Reg, round3Rk4Reg)

  val stage1Valid = RegNext(in.valid, false.B)
  val stage2Valid = RegNext(stage1Valid, false.B)
  val stage3Valid = RegNext(stage2Valid, false.B)
  val opReg = RegEnable(op, in.valid)
  val opReg2 = RegEnable(opReg, stage1Valid)
  val opReg3 = RegEnable(opReg2, stage2Valid)
  val resultReg = RegEnable(Mux1H(Seq(
    opReg3.round -> roundResult,
    opReg3.keyexpansion -> expansionResult
  )), stage3Valid)

  out.bits.vd := resultReg
  out.valid := RegNext(stage3Valid, false.B)
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
