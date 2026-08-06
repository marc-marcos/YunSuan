package yunsuan.vector.v2.Crypto

import _root_.circt.stage._
import chisel3._
import chisel3.experimental.SourceInfo
import chisel3.util._
import yunsuan.vector.Common._
import yunsuan.vector.v2.Crypto.Utils.Zvkned.subBytes

import scala.collection.immutable.SeqMap
import scala.language.implicitConversions

class VSm extends Module {
  import VSm._
  import yunsuan.vector.v2.Crypto.Utils.Zvksed._

  val in = IO(Input(ValidIO(new In)))
  val out = IO(Output(new Out))
  val op = in.op
  val rkey = in.vs2
  val uimm = in.uimm
  val x = in.vs3

  val rk3 = rkey(127, 96)
  val rk2 = rkey(95, 64)
  val rk1 = rkey(63, 32)
  val rk0 = rkey(31, 0)

  val x3 = x(127, 96)
  val x2 = x(95, 64)
  val x1 = x(63, 32)
  val x0 = x(31, 0)

  // vsm4r

  val B0 = x1 ^ x2 ^ x3 ^ rk0
  val S0 = sm4SubWord(B0)
  val x4 = sm4Round(x0, S0)

  val B1 = x2 ^ x3 ^ x4 ^ rk1
  val S1 = sm4SubWord(B1)
  val x5 = sm4Round(x1, S1)

  val B2 = x3 ^ x4 ^ x5 ^ rk2
  val S2 = sm4SubWord(B2)
  val x6 = sm4Round(x2, S2)

  val B3 = x4 ^ x5 ^ x6 ^ rk3
  val S3 = sm4SubWord(B3)
  val x7 = sm4Round(x3, S3)

  val round_result = Cat(x7, x6, x5, x4)

  // vsm4k

  val B0k = rk1 ^ rk2 ^ rk3 ^ ck(4.U*uimm)
  val S0k = sm4SubWord(B0k)
  val rk4 = sm4RoundKey(rk0, S0k)

  val B1k = rk2 ^ rk3 ^ rk4 ^ ck(4.U*uimm+1.U)
  val S1k = sm4SubWord(B1k)
  val rk5 = sm4RoundKey(rk1, S1k)

  val B2k = rk3 ^ rk4 ^ rk5 ^ ck(4.U*uimm+2.U)
  val S2k = sm4SubWord(B2k)
  val rk6 = sm4RoundKey(rk2, S2k)

  val B3k = rk4 ^ rk5 ^ rk6 ^ ck(4.U*uimm+3.U)
  val S3k = sm4SubWord(B3k)
  val rk7 = sm4RoundKey(rk3, S3k)

  val expansion_result = Cat(rk7, rk6, rk5, rk4)

  out.vd := Mux1H(Seq(
    in.op.round -> round_result,
    in.op.keyexpansion -> expansion_result
  ))
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
