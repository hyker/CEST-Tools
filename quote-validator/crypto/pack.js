import Data from "./data.js";

const U8_LENGTH = 1
const U16_LENGTH = 2
const U32_LENGTH = 4
const U64_LENGTH = 8

export const unpackNumber = bytes => {
  return bytes.getUint8Array().reduce((acc, byte) => (acc << 8) + byte, 0)
}

export const unpackLENumber = bytes => {
  return bytes.getUint8Array().reduceRight((acc, byte) => (acc << 8) + byte, 0)
}

export const packU8 = n => {
  if (isNaN(n)) throw new Error(`n must be a number.`)
  return new Data(new Uint8Array([
    (n & 0xFF)
  ]))
}

export const packU16 = n => {
  if (isNaN(n)) throw new Error(`n must be a number.`)
  return new Data(new Uint8Array([
    (n & 0xFF00) >> 8,
    (n & 0x00FF)
  ]))
}

export const packU32 = n => {
  if (isNaN(n)) throw new Error(`n must be a number.`)
  return new Data(new Uint8Array([
    (n & 0xFF000000) >> 24,
    (n & 0x00FF0000) >> 16,
    (n & 0x0000FF00) >> 8,
    (n & 0x000000FF)
  ]))
}

export const packBytes = bytes => {
  if (typeof bytes === 'string' || bytes instanceof String) {
    return packBytes(Data.fromUTF8(bytes))
  } else if (bytes) {
    return Data.join([
      packU16(bytes.length),
      bytes
    ])
  } else {
    return packU16(0)
  }
}

export class Seeker {

  constructor(data) {
    this.pos = 0
    this.remaining = data.length
    this.data = data
  }

  insert(data) {
    if (this.pos + data.length > this.data.length) {
      throw new Error(`Can't pack: Out of bounds. (pos=${this.pos}, len=${data.length}, available=${this.remaining})`)
    }
    this.data.set(data, this.pos)
  }

  extract(length) {
    if (this.pos + length > this.data.length) {
      throw new Error(`Can't extract: Out of bounds. (pos=${this.pos}, len=${length}, available=${this.remaining})`)
    }
    const data = this.data.slice(this.pos, this.pos + length)
    this.pos += length
    this.remaining -= length;
    return data
  }

  extractU8() {
    return unpackNumber(this.extract(U8_LENGTH))
  }

  extractU16() {
    return unpackNumber(this.extract(U16_LENGTH))
  }

  extractLEU16() {
    return unpackLENumber(this.extract(U16_LENGTH))
  }

  extractU32() {
    return unpackNumber(this.extract(U32_LENGTH))
  }

  extractLEU32() {
    return unpackLENumber(this.extract(U32_LENGTH))
  }

  extractU64() {
    return unpackNumber(this.extract(U64_LENGTH))
  }

  extractLEU64() {
    return unpackLENumber(this.extract(U64_LENGTH))
  }

  pack(data) {
    if (U16_LENGTH + this.pos + data.length > this.data.length) {
      throw new Error(`Can't pack: Out of bounds. (pos=${this.pos}, len=${data.length}, available=${this.data.length - this.pos})`)
    }
    insert(packU16(data.length))
    insert(data)
  }

  unpack() {
    const length = unpackNumber(this.data.slice(this.pos, this.pos + U16_LENGTH))
    if (this.pos + U16_LENGTH + length > this.data.length) {
      throw new Error(`Can't unpack: Out of bounds. (pos=${this.pos + U16_LENGTH}, len=${length}, available=${this.data.length - this.pos})`)
    }
    const data = this.data.slice(this.pos + U16_LENGTH, this.pos + U16_LENGTH + length)
    this.pos += U16_LENGTH + length
    return data
  }

  skip(length) {
    this.pos += length;
    this.remaining -= length;
  }

};
