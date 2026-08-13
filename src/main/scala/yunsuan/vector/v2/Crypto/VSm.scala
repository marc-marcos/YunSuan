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

  // The four SM4 rounds are split into two pipeline stages.  The first
  // stage consumes the input accepted in this cycle and the second stage
  // produces the result in the following cycle.

  val B0 = x1 ^ x2 ^ x3 ^ rk0
  val S0 = sm4SubWord(B0)

  // B1 = x2 ^ x3 ^ x4 ^ rk1 with x4 = x0 ^ L(S0) re-associated as
  // B1 = (x0 ^ x2 ^ x3 ^ rk1) ^ L(S0): the P1 term depends only on the inputs,
  // so it is computed in parallel with the S-box instead of after it.
  val L0 = sm4Linear(S0)
  val x4 = x0 ^ L0
  val P1 = x0 ^ x2 ^ x3 ^ rk1
  val B1 = P1 ^ L0
  val S1 = sm4SubWord(B1)
  val x5 = sm4Round(x1, S1)

  val roundX2Reg = RegEnable(x2, in.valid)
  val roundX3Reg = RegEnable(x3, in.valid)
  val roundX4Reg = RegEnable(x4, in.valid)
  val roundX5Reg = RegEnable(x5, in.valid)
  val roundRk2Reg = RegEnable(rk2, in.valid)
  val roundRk3Reg = RegEnable(rk3, in.valid)

  val B2 = roundX3Reg ^ roundX4Reg ^ roundX5Reg ^ roundRk2Reg
  val S2 = sm4SubWord(B2)
  val L2 = sm4Linear(S2)
  val x6 = roundX2Reg ^ L2
  val P3 = roundX2Reg ^ roundX4Reg ^ roundX5Reg ^ roundRk3Reg
  val B3 = P3 ^ L2
  val S3 = sm4SubWord(B3)
  val x7 = sm4Round(roundX3Reg, S3)

  val roundResult = Cat(x7, x6, roundX5Reg, roundX4Reg)

  // vsm4k

  val B0k = rk1 ^ rk2 ^ rk3 ^ ck(4.U*uimm)
  val S0k = sm4SubWord(B0k)

  // Same re-association as the round path: B1k = (rk0 ^ rk2 ^ rk3 ^ ck) ^ L'(S0k),
  // with the P1k term computed in parallel with the S-box.
  val L0k = sm4KeyLinear(S0k)
  val rk4 = rk0 ^ L0k
  val P1k = rk0 ^ rk2 ^ rk3 ^ ck(4.U*uimm+1.U)
  val B1k = P1k ^ L0k
  val S1k = sm4SubWord(B1k)
  val rk5 = sm4RoundKey(rk1, S1k)

  val expansionRk2Reg = RegEnable(rk2, in.valid)
  val expansionRk3Reg = RegEnable(rk3, in.valid)
  val expansionRk4Reg = RegEnable(rk4, in.valid)
  val expansionRk5Reg = RegEnable(rk5, in.valid)
  val expansionCk2Reg = RegEnable(ck(4.U * uimm + 2.U), in.valid)
  val expansionCk3Reg = RegEnable(ck(4.U * uimm + 3.U), in.valid)

  val B2k = expansionRk3Reg ^ expansionRk4Reg ^ expansionRk5Reg ^ expansionCk2Reg
  val S2k = sm4SubWord(B2k)
  val L2k = sm4KeyLinear(S2k)
  val rk6 = expansionRk2Reg ^ L2k
  val P3k = expansionRk2Reg ^ expansionRk4Reg ^ expansionRk5Reg ^ expansionCk3Reg
  val B3k = P3k ^ L2k
  val S3k = sm4SubWord(B3k)
  val rk7 = sm4RoundKey(expansionRk3Reg, S3k)

  val expansionResult = Cat(rk7, rk6, expansionRk5Reg, expansionRk4Reg)

  val stage1Valid = RegNext(in.valid, false.B)
  val stage2Valid = RegNext(stage1Valid, false.B)
  val opReg = RegEnable(op, in.valid)
  val resultReg = RegEnable(Mux1H(Seq(
    opReg.round -> roundResult,
    opReg.keyexpansion -> expansionResult
  )), stage1Valid)

  out.bits.vd := resultReg
  out.valid := stage2Valid
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
