package yunsuan.vector.v2.Crypto

import chisel3._
import chisel3.util._

class VGHash extends Module {
  import VGHash._

  val in = IO(Input(ValidIO(new In)))
  val out = IO(Output(ValidIO(new Out)))

  private def reverseBitsInBytes(value: UInt): UInt = {
    Cat((0 until 16).reverse.map(i => Reverse(value(8 * i + 7, 8 * i))))
  }

  private def multiplyRounds(
    multiplier: UInt,
    initialProduct: UInt,
    initialMultiplicand: UInt,
    firstBit: Int,
    rounds: Int
  ): (UInt, UInt) = {
    (firstBit until firstBit + rounds).foldLeft((initialProduct, initialMultiplicand)) {
      case ((product, multiplicand), bit) =>
        val nextProduct = Mux(multiplier(bit), product ^ multiplicand, product)
        val shifted = Cat(multiplicand(126, 0), 0.U(1.W))
        val nextMultiplicand = shifted ^ Mux(multiplicand(127), 0x87.U(DLEN.W), 0.U(DLEN.W))
        (nextProduct, nextMultiplicand)
    }
  }

  val multiplier = reverseBitsInBytes(in.bits.y ^ in.bits.x)
  val multiplicand = reverseBitsInBytes(in.bits.h)

  val (productStage1, multiplicandStage1) =
    multiplyRounds(multiplier, 0.U(DLEN.W), multiplicand, firstBit = 0, rounds = 64)

  val s1_multiplier = RegEnable(multiplier, in.valid)
  val s1_product = RegEnable(productStage1, in.valid)
  val s1_multiplicand = RegEnable(multiplicandStage1, in.valid)
  val s1_valid = RegNext(in.valid)

  val (s2_productStage2, _) =
    multiplyRounds(s1_multiplier, s1_product, s1_multiplicand, firstBit = 64, rounds = 64)

  val s2_result = RegEnable(reverseBitsInBytes(productStage2), s1_valid)
  val s2_valid = RegNext(s1_valid)

  out.bits.vd := s2_result
  out.valid := s2_valid
}

object VGHash {
  val DLEN = 128

  class In extends Bundle {
    val y = UInt(DLEN.W)
    val x = UInt(DLEN.W)
    val h = UInt(DLEN.W)
  }

  class Out extends Bundle {
    val vd = UInt(DLEN.W)
  }
}
