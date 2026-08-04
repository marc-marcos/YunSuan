package yunsuan.vector.v2.Crypto

import chisel3._
import chisel3.util._

class VGHash extends Module {
  val in = IO(Input(new Bundle {
    val y = UInt(128.W)
    val x = UInt(128.W)
    val h = UInt(128.W)
  }))
  val out = IO(Output(UInt(128.W)))

  private def reverseBitsInBytes(value: UInt): UInt = {
    Cat((0 until 16).reverse.map(i => Reverse(value(8 * i + 7, 8 * i))))
  }

  val multiplier = reverseBitsInBytes(in.y ^ in.x)
  val multiplicand = reverseBitsInBytes(in.h)

  val products = Wire(Vec(129, UInt(128.W)))
  val shiftedMultiplicands = Wire(Vec(129, UInt(128.W)))
  products(0) := 0.U
  shiftedMultiplicands(0) := multiplicand

  for (bit <- 0 until 128) {
    products(bit + 1) := Mux(multiplier(bit), products(bit) ^ shiftedMultiplicands(bit), products(bit))
    shiftedMultiplicands(bit + 1) :=
      (shiftedMultiplicands(bit) << 1) ^ Mux(shiftedMultiplicands(bit)(127), 0x87.U(128.W), 0.U)
  }

  out := reverseBitsInBytes(products(128))
}