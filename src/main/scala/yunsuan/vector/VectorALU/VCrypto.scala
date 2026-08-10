
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
  val isVclmul = io.in.bits.opcode.isVclmul || io.in.bits.opcode.isVclmulh
  val isAesDf = io.in.bits.opcode.isVaesdf
  val isAesDm = io.in.bits.opcode.isVaesdm
  val isAesEf = io.in.bits.opcode.isVaesef
  val isAesEm = io.in.bits.opcode.isVaesem
  val isAesKf1 = io.in.bits.opcode.isVaeskf1
  val isAesKf2 = io.in.bits.opcode.isVaeskf2
  val isAes = isAesZero || isAesDf || isAesDm || isAesEf || isAesEm || isAesKf1 || isAesKf2

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

  val vclmul_d1 = RegEnable(result, io.in.valid)
  val vclmul_d2 = RegEnable(vclmul_d1, RegNext(io.in.valid, false.B))

  val aesZeroResult = io.in.bits.old_vd ^ io.in.bits.vs2
  val aesZeroResult_d1 = RegEnable(aesZeroResult, io.in.valid)
  val aesZeroResult_d2 = RegEnable(aesZeroResult_d1, RegNext(io.in.valid, false.B))

  val aes = Module(new VAes)
  aes.in.valid := io.in.valid
  aes.in.bits.op.em := isAesEm
  aes.in.bits.op.ef := isAesEf
  aes.in.bits.op.dm := isAesDm
  aes.in.bits.op.df := isAesDf
  aes.in.bits.op.kf1 := isAesKf1
  aes.in.bits.op.kf2 := isAesKf2
  aes.in.bits.vs3 := io.in.bits.old_vd
  aes.in.bits.vs2 := io.in.bits.vs2
  aes.in.bits.uimm := io.in.bits.uimm

  val isAesZero_d2 = ShiftRegister(Mux(io.in.valid, isAesZero, false.B), 2)
  val aesResult_d2 = Mux(isAesZero_d2, aesZeroResult_d2, aes.out.bits.vd)

  val vclmul_d1 = RegEnable(result, io.in.valid)
  val vclmul_d2 = RegEnable(vclmul_d1, RegNext(io.in.valid, false.B))

  val isVclmul_d2 = ShiftRegister(Mux(io.in.valid, isVclmul, false.B), 2)
  val isAes_d2 = ShiftRegister(Mux(io.in.valid, isAes, false.B), 2)
  val valid_d2 = ShiftRegister(io.in.valid, 2)


  io.out.bits.vd    := MuxCase(0.U(128.W), Seq(
                                 isAes_d2 -> aesResult_d2,
                                 isVclmul_d2 -> vclmul_d2
  ))

  io.out.bits.vxsat := false.B
  io.out.valid      := valid_d2
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
    val uimm = UInt(5.W)
  }

  class Out extends Bundle {
    val vd = UInt(128.W)
    val vxsat = Bool()
  }
}
