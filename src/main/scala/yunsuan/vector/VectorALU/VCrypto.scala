
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

  val isHigh = io.in.bits.opcode.isVclmulh
  val isAesZero = io.in.bits.opcode.isVaesz
  val isVclmul = io.in.bits.opcode.isVclmul || io.in.bits.opcode.isVclmulh
  val isAesDf = io.in.bits.opcode.isVaesdf
  val isAesDm = io.in.bits.opcode.isVaesdm
  val isAesEf = io.in.bits.opcode.isVaesef
  val isAesEm = io.in.bits.opcode.isVaesem
  val isAesKf1 = io.in.bits.opcode.isVaeskf1
  val isAesKf2 = io.in.bits.opcode.isVaeskf2
  val isSm4k = io.in.bits.opcode.isVsm4k
  val isSm4r = io.in.bits.opcode.isVsm4r
  val isAes = isAesZero || isAesDf || isAesDm || isAesEf || isAesEm || isAesKf1 || isAesKf2
  val isGHash = io.in.bits.opcode.isVghsh || io.in.bits.opcode.isVgmul
  val isSm = isSm4k || isSm4r

  val hi_hi = Wire(UInt(64.W))
  val hi_lo = Wire(UInt(64.W))
  val lo_hi = Wire(UInt(64.W))
  val lo_lo = Wire(UInt(64.W))

  val valid_d2 = ShiftRegister(io.in.valid, 2)
  val valid_d3 = ShiftRegister(io.in.valid, 3)
  val valid_d4 = ShiftRegister(io.in.valid, 4)

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
  val vclmul_d3 = RegEnable(vclmul_d2, valid_d2)
  val vclmul_d4 = RegEnable(vclmul_d3, valid_d3)

  val aesZeroResult = io.in.bits.old_vd ^ io.in.bits.vs2
  val aesZeroResult_d1 = RegEnable(aesZeroResult, io.in.valid)
  val aesZeroResult_d2 = RegEnable(aesZeroResult_d1, RegNext(io.in.valid, false.B))
  val aesZeroResult_d3 = RegEnable(aesZeroResult_d2, RegNext(RegNext(io.in.valid, false.B)))

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
  val aesResult_d3 = RegEnable(aesResult_d2, valid_d2)
  val aesResult_d4 = RegEnable(aesResult_d3, valid_d3)

  // GHash

  val ghash = Module(new VGHash)
  ghash.in.valid := io.in.valid
  // vghsh: vd = (old_vd ^ vs1) * vs2; vgmul: vd = old_vd * vs2
  ghash.in.bits.y := io.in.bits.old_vd
  ghash.in.bits.x := Mux(io.in.bits.opcode.isVghsh, io.in.bits.vs1, 0.U(128.W))
  ghash.in.bits.h := io.in.bits.vs2

  val ghashResult_d3 = RegEnable(ghash.out.bits.vd, valid_d2)
  val ghashResult_d4 = RegEnable(ghashResult_d3, valid_d3)

  val isVclmul_d4 = ShiftRegister(Mux(io.in.valid, isVclmul, false.B), 4)
  val isAes_d4 = ShiftRegister(Mux(io.in.valid, isAes, false.B), 4)
  val isGhash_d4 = ShiftRegister(Mux(io.in.valid, isGHash, false.B), 4)
  val isSm_d4 = ShiftRegister(Mux(io.in.valid, isSm, false.B), 4)

  // Zvksed vsm4k/vsm4r

  val sm = Module(new VSm)
  sm.in.valid := io.in.valid
  sm.in.bits.op.round := isSm4r
  sm.in.bits.op.keyexpansion := isSm4k
  sm.in.bits.vs3 := io.in.bits.old_vd
  sm.in.bits.vs2 := io.in.bits.vs2
  sm.in.bits.uimm := io.in.bits.uimm

  io.out.bits.vd    := MuxCase(0.U(128.W), Seq(
                                 isAes_d4 -> aesResult_d4,
                                 isVclmul_d4 -> vclmul_d4,
                                 isGhash_d4 -> ghashResult_d4,
                                 isSm_d4 -> sm.out.bits.vd
  ))

  io.out.bits.vxsat := false.B
  io.out.valid      := valid_d4
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
    val vghsh   = 9.U(4.W)
    val vgmul   = 10.U(4.W)
    val vsm4k   = 11.U(4.W)
    val vsm4r   = 12.U(4.W)
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
