package yunsuan.vector.v2.Crypto

import chisel3._
import chisel3.util._
import yunsuan.vector.Common._

import scala.language.implicitConversions

package object Utils {
  /**
   * Utils for SHA256/512
   */
  object Zvknhb {
    private[Zvknhb] class sum1chModule(EEW: Int) extends Module {
      val h, g, f, e, kw = IO(Input(UInt(EEW.W)))
      val t1 = IO(Output(UInt(EEW.W)))

      t1 := h + sum1(EEW)(e) + ch(e, f, g) + kw
    }

    private[Zvknhb] object sum1chModule {
      def apply(
        EEW: Int,
      )(
        h: UInt, g: UInt, f: UInt, e: UInt, kw: UInt,
      ): UInt = {
        val sum1chMod = Module(new sum1chModule(EEW))
        sum1chMod.h := h
        sum1chMod.g := g
        sum1chMod.f := f
        sum1chMod.e := e
        sum1chMod.kw := kw
        sum1chMod.t1
      }
    }

    private[Zvknhb] class sum0majModule(EEW: Int) extends Module {
      val c, b, a = IO(Input(UInt(EEW.W)))
      val t2 = IO(Output(UInt(EEW.W)))

      t2 := sum0(EEW)(a) + maj(a, b, c)
    }

    private[Zvknhb] object sum0majModule {
      def apply(
        EEW: Int,
      )(
        c: UInt, b: UInt, a: UInt,
      ): UInt = {
        val sum0majMod = Module(new sum0majModule(EEW))
        sum0majMod.c := c
        sum0majMod.b := b
        sum0majMod.a := a
        sum0majMod.t2
      }
    }

    object SHA512 {
      val EEW = 64

      def sum0(x: UInt): UInt = x.rotateRight(28) ^ x.rotateRight(34) ^ x.rotateRight(39)

      def sum1(x: UInt): UInt = x.rotateRight(14) ^ x.rotateRight(18) ^ x.rotateRight(41)

      def sum0maj: (UInt, UInt, UInt) => UInt = sum0majModule(EEW)

      def sum1ch: (UInt, UInt, UInt, UInt, UInt) => UInt = sum1chModule(EEW)

      def sig0(x: UInt): UInt = x.rotateRight(1) ^ x.rotateRight(8) ^ x.>>(7).asUInt

      def sig1(x: UInt): UInt = x.rotateRight(19) ^ x.rotateRight(61) ^ x.>>(6).asUInt
    }

    object SHA256 {
      val EEW = 32

      def sum0(x: UInt): UInt = x.rotateRight(2) ^ x.rotateRight(13) ^ x.rotateRight(22)

      def sum1(x: UInt): UInt = x.rotateRight(6) ^ x.rotateRight(11) ^ x.rotateRight(25)

      def sum0maj: (UInt, UInt, UInt) => UInt = sum0majModule(EEW)

      def sum1ch: (UInt, UInt, UInt, UInt, UInt) => UInt = sum1chModule(EEW)

      def sig0(x: UInt): UInt = x.rotateRight(7) ^ x.rotateRight(18) ^ x.>>(3).asUInt

      def sig1(x: UInt): UInt = x.rotateRight(17) ^ x.rotateRight(19) ^ x.>>(10).asUInt
    }

    def ch(x: UInt, y: UInt, z: UInt): UInt = (x & y) ^ ((~x).asUInt & z)

    def maj(x: UInt, y: UInt, z: UInt): UInt = (x & y) ^ (x & z) ^ (y & z)

    def sum0(EEW: Int)(x: UInt): UInt = EEW match {
      case 32 => SHA256.sum0(x)
      case 64 => SHA512.sum0(x)
    }

    def sum1(EEW: Int)(x: UInt): UInt = EEW match {
      case 32 => SHA256.sum1(x)
      case 64 => SHA512.sum1(x)
    }
  }

  /**
   * Utils for AES
   */
  object Zvkned {
    def addRound128(state: UInt, rkey: UInt): UInt = {
      require(state.getWidth == 128 && rkey.getWidth == 128)

      val ark = state ^ rkey
      ark
    }

    def subBytes(state: UInt): UInt = {
      require(state.getWidth == 128)
      val bytes = state.splitToVec(num = 16, w = 8)
      Cat(bytes.map(B => kVAESXEncSBox(B)).reverse)
    }

    def subWord(word: UInt): UInt = {
      val bytes = word.splitToVec(num = 4, w = 8)
      Cat(bytes.map(B => kVAESXEncSBox(B)).reverse)
    }

    def subBytesInv(state: UInt): UInt = {
      require(state.getWidth == 128)
      val bytes = state.splitToVec(num = 16, w = 8)
      Cat(bytes.map(B => kVAESXDecSBox(B)).reverse)
    }

    //       col3 col2 col1 col0
    // row3   b15  b11  b7   b3
    // row2   b14  b10  b6   b2
    // row1   b13  b9   b5   b1
    // row0   b12  b8   b4   b0
    def shiftRows(state: UInt): UInt = {
      // matrix4x4(0,0): b0 -> state(7,0)
      // matrix4x4(0,1): b4 -> state(39:32)
      // ...
      val matrix4x4: Seq[Seq[UInt]] = state.splitToVec(num = 4, w = 32).map(_.splitToVec(num = 4, w = 8)).transpose
      val shiftedRows = matrix4x4.zipWithIndex.map {
        case (row, i) => VecInit(row).rotateDown(i)
      }
      Cat(shiftedRows.transpose.flatten.reverse)
    }

    def shiftRowsInv(state: UInt): UInt = {
      val matrix4x4: Seq[Seq[UInt]] = state.splitToVec(num = 4, w = 32).map(_.splitToVec(num = 4, w = 8)).transpose
      val shiftedRows = matrix4x4.zipWithIndex.map {
        case (row, i) => VecInit(row).rotateUp(i)
      }
      Cat(shiftedRows.transpose.flatten.reverse)
    }

    def mixColumns(state: UInt): UInt = {
      val cols = state.splitToVec(num = 4, w = 32)
      Cat(cols.map(mixColumn).reverse)
    }

    def mixColumnsInv(state: UInt): UInt = {
      val cols = state.splitToVec(num = 4, w = 32)
      Cat(cols.map(inMixColumn).reverse)
    }

    def mixColumn(col: UInt): UInt = {
      val bytes = col.splitToVec(num = 4, w = 8)
      val gfMul1s = VecInit(bytes.map(gfMul1))
      val gfMul2s = VecInit(bytes.map(gfMul2))
      val gfMul3s = VecInit(bytes.map(gfMul3))
      val b0 = gfMul2s(0) ^ gfMul3s(1) ^ gfMul1s(2) ^ gfMul1s(3)
      val b1 = gfMul2s(1) ^ gfMul3s(2) ^ gfMul1s(3) ^ gfMul1s(0)
      val b2 = gfMul2s(2) ^ gfMul3s(3) ^ gfMul1s(0) ^ gfMul1s(1)
      val b3 = gfMul2s(3) ^ gfMul3s(0) ^ gfMul1s(1) ^ gfMul1s(2)
      Cat(b3, b2, b1, b0)
    }

    def inMixColumn(col: UInt): UInt = {
      val bytes = col.splitToVec(num = 4, w = 8)
      val gfMul9s = VecInit(bytes.map(gfMul9))
      val gfMulBs = VecInit(bytes.map(gfMulB))
      val gfMulDs = VecInit(bytes.map(gfMulD))
      val gfMulEs = VecInit(bytes.map(gfMulE))
      val b0 = gfMulEs(0) ^ gfMulBs(1) ^ gfMulDs(2) ^ gfMul9s(3)
      val b1 = gfMulEs(1) ^ gfMulBs(2) ^ gfMulDs(3) ^ gfMul9s(0)
      val b2 = gfMulEs(2) ^ gfMulBs(3) ^ gfMulDs(0) ^ gfMul9s(1)
      val b3 = gfMulEs(3) ^ gfMulBs(0) ^ gfMulDs(1) ^ gfMul9s(2)
      Cat(b3, b2, b1, b0)
    }

    // It's just a fake zero(0)
    private val O = false.B

    def gfMul1(x: UInt) = x

    def gfMul2(x: UInt) = {
      //  lsb                                msb
      val a :: b :: c :: d :: e :: f :: g :: h :: Nil = x.asBools.toList
      // (x << 1).asUInt ^ Mux(x.head(1).asBool, 0x1b.U, 0.U)
      // 0 ^ x = x
      0.U ^
        Cat(g, f, e, d, c, b, a, O) ^
        Cat(O, O, O, h, h, O, h, h)
    }

    def gfMul4(x: UInt): UInt = {
      val a :: b :: c :: d :: e :: f :: g :: h :: Nil = x.asBools.toList
      0.U ^
        Cat(f, e, d, c, b, a, O, O) ^
        Cat(O, O, h, h, O, h, h, O) ^
        Cat(O, O, O, g, g, O, g, g)
    }

    def gfMul8(x: UInt): UInt = {
      val a :: b :: c :: d :: e :: f :: g :: h :: Nil = x.asBools.toList
      0.U ^
        Cat(e, d, c, b, a, O, O, O) ^
        Cat(O, h, h, O, h, h, O, O) ^
        Cat(O, O, g, g, O, g, g, O) ^
        Cat(O, O, O, f, f, O, f, f)
    }

    def gfMul3(x: UInt): UInt = gfMul2(x) ^ gfMul1(x)

    def gfMul9(x: UInt): UInt = gfMul8(x) ^ gfMul1(x)

    def gfMulB(x: UInt): UInt = gfMul8(x) ^ gfMul2(x) ^ gfMul1(x)

    def gfMulD(x: UInt): UInt = gfMul8(x) ^ gfMul4(x) ^ gfMul1(x)

    def gfMulE(x: UInt): UInt = gfMul8(x) ^ gfMul4(x) ^ gfMul2(x)

    val kVAESXEncSBox = VecInit(Seq(
      //        00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
      /* 00 */ 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
      /* 10 */ 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
      /* 20 */ 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
      /* 30 */ 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
      /* 40 */ 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
      /* 50 */ 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
      /* 60 */ 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
      /* 70 */ 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
      /* 80 */ 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
      /* 90 */ 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
      /* A0 */ 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
      /* B0 */ 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
      /* C0 */ 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
      /* D0 */ 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
      /* E0 */ 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
      /* F0 */ 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ).map(_.U(8.W)))

    val kVAESXDecSBox = VecInit(Seq(
      //        00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
      /* 00 */ 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
      /* 10 */ 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
      /* 20 */ 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
      /* 30 */ 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
      /* 40 */ 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
      /* 50 */ 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
      /* 60 */ 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
      /* 70 */ 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
      /* 80 */ 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
      /* 90 */ 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
      /* A0 */ 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
      /* B0 */ 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
      /* C0 */ 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
      /* D0 */ 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
      /* E0 */ 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
      /* F0 */ 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ).map(_.U(8.W)))
  }

  /**
   * Utils for SM4
   */
  object Zvksed {
    def rol32(x: UInt, n: UInt): UInt = {
      require(x.getWidth == 32)
      x.rotateLeft(n(4, 0))
    }

    def sm4SubWord(in: UInt): UInt = {
      Cat(in.splitToVec(num = 4, w = 8).map(sm4SubBox).reverse)
    }

    // Algebraic SM4 S-box: SM4_Sbox(x) = M_out * (M_in * x ^ C_in)^-1 ^ C_out,
    // the inverse computed in the tower field GF((2^4)^2) = GF(2^4)[y]/(y^2+y+lam),
    // GF(2^4) with poly x^4+x+1 (0x13). Constants derived from the AESENCLAST
    // decomposition; equivalence vs sm4_sbox_table is asserted at elaboration.
    private val sm4Gf4Lam = 0xD
    private val sm4MIn  = Seq(0x42, 0x08, 0x96, 0x87, 0x99, 0x6D, 0x2B, 0x02)
    private val sm4CIn  = 0x01
    private val sm4MOut = Seq(0xAB, 0x2A, 0xA1, 0x50, 0x8A, 0x26, 0x14, 0xB0)
    private val sm4COut = 0xD3

    private val gf4InvTable = VecInit(Seq(0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8).map(_.U(4.W)))

    // y = M*x ^ c over GF(2)^8; M as 8 row-bytes (row i = input mask of output bit i)
    private def affine8(m: Seq[Int], c: Int, x: UInt): UInt = {
      require(x.getWidth == 8)
      Cat((7 to 0 by -1).map { i =>
        val acc = (0 until 8).filter(j => ((m(i) >> j) & 1) == 1).map(j => x(j)).foldLeft(false.B)(_ ^ _)
        acc ^ ((c >> i) & 1).B
      })
    }

    // GF(2^4) multiply, poly x^4+x+1
    private def gf4Mul(a: UInt, b: UInt): UInt = {
      require(a.getWidth == 4 && b.getWidth == 4)
      val a3 = a(3); val a2 = a(2); val a1 = a(1); val a0 = a(0)
      val b3 = b(3); val b2 = b(2); val b1 = b(1); val b0 = b(0)
      val p0 = (a0 & b0) ^ (a1 & b3) ^ (a2 & b2) ^ (a3 & b1)
      val p1 = (a0 & b1) ^ (a1 & b0) ^ (a1 & b3) ^ (a2 & b2) ^ (a3 & b1) ^ (a2 & b3) ^ (a3 & b2)
      val p2 = (a0 & b2) ^ (a1 & b1) ^ (a2 & b0) ^ (a2 & b3) ^ (a3 & b2) ^ (a3 & b3)
      val p3 = (a0 & b3) ^ (a1 & b2) ^ (a2 & b1) ^ (a3 & b0) ^ (a3 & b3)
      Cat(p3, p2, p1, p0)
    }

    // GF(2^4) squaring (linear over GF(2)^4)
    private def gf4Square(a: UInt): UInt = {
      require(a.getWidth == 4)
      Cat(a(3), a(3) ^ a(1), a(2), a(2) ^ a(0))
    }

    // Inverse in GF((2^4)^2): u = a1*y + a0, y^2 = y + lam
    // u^-1 = (a1*T^-1)*y + (a0^a1)*T^-1, T = a0^2 ^ a0*a1 ^ lam*a1^2
    private def gfInv8(u: UInt): UInt = {
      require(u.getWidth == 8)
      val a1 = u(7, 4)
      val a0 = u(3, 0)
      val t = gf4Square(a0) ^ gf4Mul(a0, a1) ^ gf4Mul(gf4Square(a1), sm4Gf4Lam.U(4.W))
      val tInv = gf4InvTable(t)
      Cat(gf4Mul(a1, tInv), gf4Mul(a0 ^ a1, tInv))
    }

    def sm4SubBox(in: UInt): UInt = {
      require(in.getWidth == 8)
      affine8(sm4MOut, sm4COut, gfInv8(affine8(sm4MIn, sm4CIn, in)))
    }

    // SM4 round linear layer: L(S) = S ^ S<<<2 ^ S<<<10 ^ S<<<18 ^ S<<<24
    def sm4Linear(s: UInt): UInt = {
      require(s.getWidth == 32)
      s ^ rol32(s, 2.U) ^ rol32(s, 10.U) ^ rol32(s, 18.U) ^ rol32(s, 24.U)
    }

    def sm4Round(x: UInt, s: UInt): UInt = {
      x ^ sm4Linear(s)
    }

    // SM4 key-expansion linear layer: L'(S) = S ^ S<<<13 ^ S<<<23
    def sm4KeyLinear(s: UInt): UInt = {
      require(s.getWidth == 32)
      s ^ rol32(s, 13.U) ^ rol32(s, 23.U)
    }

    def sm4RoundKey(x: UInt, s: UInt): UInt = {
      x ^ sm4KeyLinear(s)
    }

    def ck(in: UInt): UInt = {
      require(in.getWidth >= 5)
      sm4_ck_table(in(4, 0))
    }

    val sm4_ck_table = VecInit(Seq(
      "h00070e15".U(32.W), "h1c232a31".U(32.W), "h383f464d".U(32.W), "h545b6269".U(32.W),
      "h70777e85".U(32.W), "h8c939aa1".U(32.W), "ha8afb6bd".U(32.W), "hc4cbd2d9".U(32.W),
      "he0e7eef5".U(32.W), "hfc030a11".U(32.W), "h181f262d".U(32.W), "h343b4249".U(32.W),
      "h50575e65".U(32.W), "h6c737a81".U(32.W), "h888f969d".U(32.W), "ha4abb2b9".U(32.W),
      "hc0c7ced5".U(32.W), "hdce3eaf1".U(32.W), "hf8ff060d".U(32.W), "h141b2229".U(32.W),
      "h30373e45".U(32.W), "h4c535a61".U(32.W), "h686f767d".U(32.W), "h848b9299".U(32.W),
      "ha0a7aeb5".U(32.W), "hbcc3cad1".U(32.W), "hd8dfe6ed".U(32.W), "hf4fb0209".U(32.W),
      "h10171e25".U(32.W), "h2c333a41".U(32.W), "h484f565d".U(32.W), "h646b7279".U(32.W),
    ))

    val sm4_sbox_table = VecInit(Seq(
      //        00    01    02    03    04    05    06    07    08    09    0A    0B    0C    0D    0E    0F
      /* 00 */ 0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
      /* 10 */ 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
      /* 20 */ 0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
      /* 30 */ 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
      /* 40 */ 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
      /* 50 */ 0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
      /* 60 */ 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
      /* 70 */ 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
      /* 80 */ 0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
      /* 90 */ 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
      /* A0 */ 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
      /* B0 */ 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
      /* C0 */ 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
      /* D0 */ 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
      /* E0 */ 0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
      /* F0 */ 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
    ).map(_.U(8.W)))

    // Elaboration-time proof: algebraic S-box == reference table on all 256 inputs.
    private def gf4MulRef(a: Int, b: Int): Int = {
      val a3 = (a >> 3) & 1; val a2 = (a >> 2) & 1; val a1 = (a >> 1) & 1; val a0 = a & 1
      val b3 = (b >> 3) & 1; val b2 = (b >> 2) & 1; val b1 = (b >> 1) & 1; val b0 = b & 1
      val p0 = (a0 & b0) ^ (a1 & b3) ^ (a2 & b2) ^ (a3 & b1)
      val p1 = (a0 & b1) ^ (a1 & b0) ^ (a1 & b3) ^ (a2 & b2) ^ (a3 & b1) ^ (a2 & b3) ^ (a3 & b2)
      val p2 = (a0 & b2) ^ (a1 & b1) ^ (a2 & b0) ^ (a2 & b3) ^ (a3 & b2) ^ (a3 & b3)
      val p3 = (a0 & b3) ^ (a1 & b2) ^ (a2 & b1) ^ (a3 & b0) ^ (a3 & b3)
      p0 | (p1 << 1) | (p2 << 2) | (p3 << 3)
    }
    private def gf4SquareRef(a: Int): Int = {
      val a0 = a & 1; val a1 = (a >> 1) & 1; val a2 = (a >> 2) & 1; val a3 = (a >> 3) & 1
      (a0 ^ a2) | (a2 << 1) | ((a1 ^ a3) << 2) | (a3 << 3)
    }
    private val gf4InvTableRef = Seq(0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8)
    private def gfInv8Ref(u: Int): Int = {
      val a1 = (u >> 4) & 0xF; val a0 = u & 0xF
      val t = gf4SquareRef(a0) ^ gf4MulRef(a0, a1) ^ gf4MulRef(gf4SquareRef(a1), sm4Gf4Lam)
      val tInv = gf4InvTableRef(t)
      (gf4MulRef(a1, tInv) << 4) | gf4MulRef(a0 ^ a1, tInv)
    }
    private def affine8Ref(m: Seq[Int], c: Int, x: Int): Int = {
      (0 until 8).foldLeft(0) { (acc, i) =>
        val p = (0 until 8).filter(j => ((m(i) >> j) & 1) == 1).foldLeft(0)((a, j) => a ^ ((x >> j) & 1))
        acc | ((p ^ ((c >> i) & 1)) << i)
      }
    }
    private def sm4SubBoxRef(x: Int): Int = {
      affine8Ref(sm4MOut, sm4COut, gfInv8Ref(affine8Ref(sm4MIn, sm4CIn, x)))
    }
    require((0 until 256).forall(i => sm4SubBoxRef(i) == sm4_sbox_table(i).litValue.toInt),
      "algebraic SM4 S-box mismatch vs reference table")

  }
}
