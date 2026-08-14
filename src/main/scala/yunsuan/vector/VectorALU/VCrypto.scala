
package yunsuan.vector.VectorALU

import chisel3._
import chisel3.util._
import yunsuan.vector.v2.Crypto.VClmul
import yunsuan.vector.v2.Crypto.VAes
import yunsuan.vector.v2.Crypto.VGHash
import yunsuan.vector.v2.Crypto.VSm

class VCrypto extends Module {
  val io = IO(new Bundle {
    val in = Flipped(ValidIO(new VCrypto.In))
    val out = ValidIO(new VCrypto.Out)
  })

  val in = io.in
  val vs1 = in.bits.vs1
  val vs2 = in.bits.vs2
  val old_vd = in.bits.old_vd
  val uimm = in.bits.uimm
  val opcode = io.in.bits.opcode
  val out = io.out
  val vd = out.bits.vd

  val isHigh = opcode.isVclmulh
  val isAesZero = opcode.isVaesz
  val isVclmul = opcode.isVclmul || opcode.isVclmulh
  val isAesDf = opcode.isVaesdf
  val isAesDm = opcode.isVaesdm
  val isAesEf = opcode.isVaesef
  val isAesEm = opcode.isVaesem
  val isAesKf1 = opcode.isVaeskf1
  val isAesKf2 = opcode.isVaeskf2
  val isSm4k = opcode.isVsm4k
  val isSm4r = opcode.isVsm4r
  val isAes = isAesZero || isAesDf || isAesDm || isAesEf || isAesEm || isAesKf1 || isAesKf2
  val isGHash = opcode.isVghsh || opcode.isVgmul
  val isSm = isSm4k || isSm4r

  val s1_valid = RegNext(in.valid)
  val s2_valid = RegNext(s1_valid)
  val s3_valid = RegNext(s2_valid)
  val s4_valid = RegNext(s3_valid)

  /**
    * Modules
    */

  val hi = Module(new VClmul)
  val lo = Module(new VClmul)
  val aes = Module(new VAes)
  val ghash = Module(new VGHash)
  val sm = Module(new VSm)

  /** Zvbc */

  val hi_hi = Wire(UInt(64.W))
  val hi_lo = Wire(UInt(64.W))
  val lo_hi = Wire(UInt(64.W))
  val lo_lo = Wire(UInt(64.W))

  hi.in.a := vs1(127, 64)
  hi.in.b := vs2(127, 64)
  hi_hi := hi.out.ch
  hi_lo := hi.out.cl

  lo.in.a := vs1(63, 0)
  lo.in.b := vs2(63, 0)
  lo_hi := lo.out.ch
  lo_lo := lo.out.cl

  val result = Cat(Mux(isHigh, hi_hi, hi_lo), Mux(isHigh, lo_hi, lo_lo))

  val s1_vclmul = RegEnable(result, in.valid)
  val s2_vclmul = RegEnable(s1_vclmul, s1_valid)
  val s3_vclmul = RegEnable(s2_vclmul, s2_valid)
  val s4_vclmul = RegEnable(s3_vclmul, s3_valid)

  /** AES */

  val aesZeroResult = old_vd ^ vs2
  val s1_aesZeroResult = RegEnable(aesZeroResult, in.valid)
  val s2_aesZeroResult = RegEnable(s1_aesZeroResult, s1_valid)
  val s3_aesZeroResult = RegEnable(s2_aesZeroResult, s2_valid)

  aes.in.valid := in.valid
  aes.in.bits.op.em := isAesEm
  aes.in.bits.op.ef := isAesEf
  aes.in.bits.op.dm := isAesDm
  aes.in.bits.op.df := isAesDf
  aes.in.bits.op.kf1 := isAesKf1
  aes.in.bits.op.kf2 := isAesKf2
  aes.in.bits.vs3 := old_vd
  aes.in.bits.vs2 := vs2
  aes.in.bits.uimm := uimm

  val s2_isAesZero = ShiftRegister(Mux(in.valid, isAesZero, false.B), 2)
  val s2_aesResult = Mux(s2_isAesZero, s2_aesZeroResult, aes.out.bits.vd)
  val s3_aesResult = RegEnable(s2_aesResult, s2_valid)
  val s4_aesResult = RegEnable(s3_aesResult, s3_valid)

  /** GHash */

  ghash.in.valid := in.valid
  ghash.in.bits.y := old_vd
  ghash.in.bits.x := Mux(opcode.isVghsh, vs1, 0.U(128.W))
  ghash.in.bits.h := vs2

  val s3_ghashResult = RegEnable(ghash.out.bits.vd, s2_valid)
  val s4_ghashResult = RegEnable(s3_ghashResult, s3_valid)

  /** SM4 */

  sm.in.valid := in.valid
  sm.in.bits.op.round := isSm4r
  sm.in.bits.op.keyexpansion := isSm4k
  sm.in.bits.vs3 := old_vd
  sm.in.bits.vs2 := vs2
  sm.in.bits.uimm := uimm

  /** Result selection */

  val s4_isVclmul = ShiftRegister(Mux(in.valid, isVclmul, false.B), 4)
  val s4_isAes = ShiftRegister(Mux(in.valid, isAes, false.B), 4)
  val s4_isGhash = ShiftRegister(Mux(in.valid, isGHash, false.B), 4)
  val s4_isSm = ShiftRegister(Mux(in.valid, isSm, false.B), 4)

  when(s4_isAes) {
    vd := s4_aesResult
  }.elsewhen(s4_isVclmul) {
    vd := s4_vclmul
  }.elsewhen(s4_isGhash) {
    vd := s4_ghashResult
  }.otherwise {
    vd := sm.out.bits.vd
  }

  out.bits.vxsat := false.B
  out.valid      := s4_valid
}

object VCrypto {
  object Opcode {
    val vclmul = 0.U(4.W)
    val vclmulh = 1.U(4.W)
    val vaesz = 2.U(4.W)
    val vaesef = 3.U(4.W)
    val vaesem = 4.U(4.W)
    val vaesdf = 5.U(4.W)
    val vaesdm = 6.U(4.W)
    val vaeskf1 = 7.U(4.W)
    val vaeskf2 = 8.U(4.W)
    val vghsh = 9.U(4.W)
    val vgmul = 10.U(4.W)
    val vsm4k = 11.U(4.W)
    val vsm4r = 12.U(4.W)
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
    def isVghsh: Bool = op === Opcode.vghsh
    def isVgmul: Bool = op === Opcode.vgmul
    def isVsm4k: Bool = op === Opcode.vsm4k
    def isVsm4r: Bool = op === Opcode.vsm4r
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
