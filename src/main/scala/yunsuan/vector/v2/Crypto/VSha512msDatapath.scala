package yunsuan.vector.v2.Crypto

import chisel3._
import chisel3.util._
import yunsuan.vector.Common._
import yunsuan.vector.v2.Crypto.Utils.Zvknhb._

class VSha512msDatapath extends Module {
  val io = IO(new Bundle {
    val uopType = Input(UInt(2.W)) // 0=ms0, 1=ms1, 2=ms2, 3=ms3
    val vs1 = Input(UInt(128.W))
    val vs2 = Input(UInt(128.W))
    val vd  = Input(UInt(128.W)) // oldVd, or a renamed intermediate
    val res = Output(UInt(128.W))
  })

  // 128-bit source -> two 64-bit words (index 0 = high word, 1 = low word)
  private val vs1Hi :: vs1Lo :: Nil = io.vs1.splitToVecN(2).toList
  private val vs2Hi :: vs2Lo :: Nil = io.vs2.splitToVecN(2).toList
  private val vdHi  :: vdLo  :: Nil = io.vd.splitToVecN(2).toList

  // TODO(user): implement
  io.res := 0.U
}

class VSha512Iteration(Sig0: Boolean) extends Module {
  val io = IO(new Bundle {
    val in = Input(new VSha512Iteration.In)
    val out = Output(new VSha512Iteration.Out)
  })

  val result = Wire(UInt(64.W))

  if (Sig0) {
    val sig0_o1 = SHA512.sig0(io.in.op1)
    val sig0_o2 = SHA512.sig0(io.in.op2)

    result(63, 0) := io.in.op0 + sig0_o1 + io.in.op3
    result(127, 64) := sig0_o2 + io.in.op1
  } else { // Sig1
    val sig1_o3 = SHA512.sig1(io.in.op3)
    val sig1_o4 = SHA512.sig1(io.in.op4)

    result(63, 0) := io.in.op0 + sig1_o3
    result(127, 64) := io.in.op1 + io.in.op2 + sig1_o4
  }

  io.out.vd := result
}

object VSha512Iteration {
  class In extends Bundle {
    val op0 = UInt(64.W)
    val op1 = UInt(64.W)
    val op2 = UInt(64.W)
    val op3 = UInt(64.W)
    val op4 = UInt(64.W)
  }

  class Out extends Bundle {
    val vd = UInt(128.W)
  }
}
