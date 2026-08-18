package yunsuan.vector.v2.Crypto

import chisel3._
import chisel3.util._

/**
 * Stateless datapath for the 4-uop vsha512ms (SHA-512 message schedule) split.
 *
 * uop schedule (per element group; each operand spans 2 registers):
 *   ms0 (uop0): partial  of W[16],W[17]   <- {vd.0, vd.1, vs2.0}
 *   ms1 (uop1): combine  of W[16],W[17]   <- {vs1.1, vs2.1, vd.0(intermediate)}
 *   ms2 (uop2): partial  of W[18],W[19]   <- {vs2.1, vs2.0, vd.1}
 *   ms3 (uop3): combine  of W[18],W[19]   <- {vd.0, vs1.0, vd.1(intermediate)}
 *
 * Each uop reads 3 registers (128-bit each) and writes 1 register.
 * The message-schedule word math (sig0/sig1) lives in Utils.Zvknhb.SHA512.
 *
 * TODO(user):
 *   1. The wrapper currently feeds a single 128-bit register per source
 *      (vs1/vs2/vd). The schedule above needs specific registers per uop,
 *      including two registers of the same operand (e.g. ms0 reads vd.0 AND
 *      vd.1). The source/register selection still has to be wired.
 *   2. The per-uop partial/combine computation below is stubbed.
 */
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

  // TODO(user): implement the message-schedule partial/combine per uopType.
  // Reference (SHA-512):
  //   W[16] = sig1(W[14]) + W[9]  + sig0(W[1]) + W[0]
  //   W[17] = sig1(W[15]) + W[10] + sig0(W[2]) + W[1]
  //   W[18] = sig1(W[16]) + W[11] + sig0(W[3]) + W[2]
  //   W[19] = sig1(W[17]) + W[12] + sig0(W[4]) + W[3]
  io.res := 0.U
}
