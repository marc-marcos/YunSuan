
package yunsuan.vector.VectorALU

import chisel3._
import chisel3.util._
import yunsuan.vector.v2.Crypto.VClmul
import yunsuan.vector.v2.Crypto.VAes

class VCrypto extends Module {
  val io = IO(new Bundle {
    val in = Flipped(ValidIO(new VCrypto.In))
    val out = ValidIO(new VCrypto.Out)
  })

  val isHigh = io.in.bits.opcode.isVclmulh
  val isAesZero = io.in.bits.opcode.isVaesz

  val hi_hi = Wire(UInt(64.W))
  val hi_lo = Wire(UInt(64.W))
  val lo_hi = Wire(UInt(64.W))
  val lo_lo = Wire(UInt(64.W))

  // Zvbc vclmul/vclmulh

  val hi = Module(new VClmul)
  hi.in.a := io.in.bits.vs1(127, 64)
  hi.in.b := io.in.bits.vs2(127, 64)
  hi_hi := hi.out.ch
  hi_lo := hi.out.cl

  val lo = Module(new VClmul)
  lo.in.a := io.in.bits.vs1(63, 0)
  lo.in.b := io.in.bits.vs2(63, 0)
  lo_hi := lo.out.ch
  lo_lo := lo.out.cl

  val result = Cat(Mux(isHigh, hi_hi, hi_lo), Mux(isHigh, lo_hi, lo_lo))

  // VAESZ is the first AES encryption round without a round key.
  val aes = Module(new VAes)
  aes.in.valid := io.in.valid
  aes.in.bits.op.em := false.B
  aes.in.bits.op.ef := true.B
  aes.in.bits.op.dm := false.B
  aes.in.bits.op.df := false.B
  aes.in.bits.vs3 := io.in.bits.old_vd
  aes.in.bits.vs2 := 0.U

  val cryptoResult = Mux(isAesZero, aes.out.vd, result)

  val stage1Result = RegEnable(cryptoResult, io.in.valid)
  val stage1Valid = RegNext(io.in.valid, false.B)

  io.out.bits.vd    := RegEnable(stage1Result, stage1Valid)
  io.out.bits.vxsat := false.B
  io.out.valid      := RegNext(stage1Valid, false.B)
}

object VCrypto {
  object Opcode {
    val vclmul  = 0.U(4.W)
    val vclmulh = 1.U(4.W)
    val vaesz   = 2.U(4.W)
    val vaesef  = 3.U(4.W)
    val vaesem  = 4.U(4.W)
    val vaesdf  = 5.U(4.W)
    val vaesdm  = 6.U(4.W)
    val vaeskf1 = 7.U(4.W)
    val vaeskf2 = 8.U(4.W)
  }

  class Opcode extends Bundle {
    val op = UInt(4.W)

    def isVclmulh: Bool = op === Opcode.vclmulh
    def isVclmul: Bool = op === Opcode.vclmul
    def isVaesef: Bool = op === Opcode.vaesef
    def isVaesem: Bool = op === Opcode.vaesem
    def isVaesdf: Bool = op === Opcode.vaesdf
    def isVaesdm: Bool = op === Opcode.vaesdm
    def isVaeskf1: Bool = op === Opcode.vaeskf1
    def isVaeskf2: Bool = op === Opcode.vaeskf2
    def isVaesz: Bool = op === Opcode.vaesz
  }

  class In extends Bundle {
    val opcode = new Opcode
    val vs1 = UInt(128.W)
    val vs2 = UInt(128.W)
    val old_vd = UInt(128.W)
  }

  class Out extends Bundle {
    val vd = UInt(128.W)
    val vxsat = Bool()
  }
}
