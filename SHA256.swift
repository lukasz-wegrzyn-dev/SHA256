//
//  SHA256.swift
//  Tests
//
//  Created by Łukasz Węgrzyn on 23/11/2021.
//

import Foundation


//MARK: Present binary with padding

extension String {

    func pad(size: Int) -> String {
        String(repeating: "0", count: size - count > 0 ? size - count : 0) + self
    }
}


//MARK: String indexing

extension String {

    subscript(i: Int) -> Character {
        return self[index(startIndex, offsetBy: i)]
    }
}

//MARK: Data as array of UInt8

extension Data {

    public var bytes: [UInt8] {
        return [UInt8](self)
    }
}


//MARK: Bits rotation algorithms

infix operator >>>
infix operator <<<

protocol BitsRotation: FixedWidthInteger, UnsignedInteger {}

extension BitsRotation {

    //Right rotation
    static func >>> (value: Self, count: Int) -> Self {
        let mask = bitWidth - 1
        let count = count & mask
        return (value >> count) | (value << (Self(-count & mask)))
    }

    //Left rotation
    static func <<< (value: Self, count: Int) -> Self {
        let mask = bitWidth - 1
        let count = count & mask
        return (value << count) | (value >> (Self(-count & mask)))
    }
}

//MARK: Values splitting extension UnsignedIntegers extension
//      Allows conversion unsigned integer of bigger type to array of smaller types values e.g UInt64 -> [UInt32, UInt32]

protocol Convertible: FixedWidthInteger, UnsignedInteger {}

extension Convertible {

    //Splitting algorithm
    private func split<T: FixedWidthInteger & UnsignedInteger>() -> [T] {
        guard Self.bitWidth > T.bitWidth else {
            return [T(self)]
        }
        var ret: [T] = []
        withUnsafeBytes(of: self) { buffer in
            let buffer8Bits = Array<UInt8>(buffer.reversed())
            for i in 0..<Self.bitWidth / T.bitWidth {
                var x: T = 0
                for j in 0..<T.bitWidth / 8 {
                    x = x << 8
                    x |= T(buffer8Bits[(i * T.bitWidth)/8 + j])
                }
                ret.append(x)
            }
        }
        return ret
    }

    func convert<T: FixedWidthInteger & UnsignedInteger>() -> [T] {
        split()
    }
}


//MARK: Merging integers array extension
//      Allows conversion array of unsigned integers of smaller type to array of bigger types integers
//      e.g [UInt16, UInt16, UInt16, UInt16] -> [UInt32, UInt32]

extension Array where Element: FixedWidthInteger & UnsignedInteger & Convertible {

    //Merge algorithm
    private func merge<T: FixedWidthInteger & UnsignedInteger>() -> [T] {
        var ret: [T] = []
        guard Element.bitWidth < T.bitWidth else {
            for x in self {
                ret.append(contentsOf: x.convert())
            }
            return ret
        }

        var x: T = 0
        for (i, element) in enumerated() {
            x = x << Element.bitWidth
            x |= T(element)
            if (i+1) % (T.bitWidth / 8) == 0 || i == count - 1 {
                ret.append(x)
                x = 0
            }
        }
        return ret
    }

    func convert<T: FixedWidthInteger & UnsignedInteger>() -> [T] {
        merge()
    }

    func showAsBinary() {
        for value in self {
            print(String(value, radix: 2).pad(size: Element.bitWidth))
        }
    }
}

//MARK: Adding extension for all unsigned integers

extension UInt8 : BitsRotation, Convertible {}
extension UInt16: BitsRotation, Convertible {}
extension UInt32: BitsRotation, Convertible {}
extension UInt64: BitsRotation, Convertible {}


//MARK: SHA256

class SHA256 {

    //Prepares data in form: [<message: unsigned 32 integers><1: one bit><00..00><message length: 64 bit>]
    private static func prepare(message: String) -> [UInt32] {
        let messageBitNumber = UInt64(message.lengthOfBytes(using: .utf8) * 8)
        let dataBitNumber = 512 * ((Int(messageBitNumber + 64 + 1) / 512) + 1)
        var data = Data(repeating: 0, count: (dataBitNumber / 8))
        let messageDataBytes = message.data(using: .utf8)?.bytes ?? []
        let messageByteNumber: [UInt8] = messageBitNumber.convert()

        data.withUnsafeMutableBytes { unsafeBytes in
            for (i, byte) in messageDataBytes.enumerated() {
                unsafeBytes[i] = byte
            }
            unsafeBytes[messageDataBytes.count] = 0b10000000
            for (i, integer) in messageByteNumber.enumerated() {
                unsafeBytes[unsafeBytes.count - (messageByteNumber.count - i)] = integer
            }
        }

        return data.bytes.convert()
    }

    //SHA256 hashing algotirhm
    static func hash(message: String) -> String {
        var h0: UInt32 = 0x6a09e667
        var h1: UInt32 = 0xbb67ae85
        var h2: UInt32 = 0x3c6ef372
        var h3: UInt32 = 0xa54ff53a
        var h4: UInt32 = 0x510e527f
        var h5: UInt32 = 0x9b05688c
        var h6: UInt32 = 0x1f83d9ab
        var h7: UInt32 = 0x5be0cd19

        let k: [UInt32] =
           [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
           0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
           0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
           0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
           0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
           0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
           0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
           0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        let preparedUInt32Array = prepare(message: message)

        for i in stride(from: 0, to: preparedUInt32Array.count, by: 16) {
            var w: [UInt32] = Array(repeating: 0, count: 64)
            for j in 0..<16 {
                w[j] = preparedUInt32Array[i+j]
            }

            for i in 16..<64 {
                let s0 = (w[i-15] >>> 7) ^ (w[i-15] >>> 18) ^ (w[i-15] >> 3)
                let s1 = (w[i-2] >>> 17) ^ (w[i-2] >>> 19) ^ (w[i-2] >> 10)
                w[i] = w[i-16] &+ s0 &+ w[i-7] &+ s1
            }

            var a: UInt32 = h0
            var b: UInt32 = h1
            var c: UInt32 = h2
            var d: UInt32 = h3
            var e: UInt32 = h4
            var f: UInt32 = h5
            var g: UInt32 = h6
            var h: UInt32 = h7

            for i in 0..<64 {
                let s1 = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = h &+ s1 &+ ch &+ k[i] &+ w[i]
                let s0 = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj

                h = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ temp2
            }

            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
            h5 = h5 &+ f
            h6 = h6 &+ g
            h7 = h7 &+ h
        }

        return "\(String(format: "%08x", h0))\(String(format: "%08x", h1))\(String(format: "%08x", h2))\(String(format: "%08x", h3))\(String(format: "%08x", h4))\(String(format: "%08x", h5))\(String(format: "%08x", h6))\(String(format: "%08x", h7))"
    }
}
