import * as base64 from "base64-js"

function isInstanceOf(types, value) {
  if (!(types instanceof Array)) {
    types = [types];
  }
  //TODO only use instance of
  //(But cant since app-konfident preforms ({Data} = require('risk-js')) and in trust-kit loads in the same class
  //effectively leading to two identical classes called Data

  return types.some(type => value instanceof type || value.constructor.name === type.name)
}

export default class Data {

  constructor(value) {
    if (isInstanceOf(Uint8Array, value)) {
      this.uint8Array = value
    } else if (isInstanceOf(ArrayBuffer, value)) {
      this.uint8Array = new Uint8Array(value)
    } else if (isInstanceOf(Array, value)) {
      this.uint8Array = new Uint8Array(value)
    } else if (Number.isInteger(value)) {
      this.uint8Array = new Uint8Array(value)
    } else {
      throw new Error(`Data must be instantiated with Uint8Array, ArrayBuffer, Array, or an integer (size in bytes). (got ${value}`)
    }
    this.dataView = new DataView(this.uint8Array.buffer, this.uint8Array.byteOffset, this.uint8Array.length)
    this.length = this.uint8Array.length
  }

  static join(dataArray) {
    const length = dataArray.map(data => {
      if (isInstanceOf([Uint8Array, ArrayBuffer, Array], data)) {
        data = new Data(data)
      } else if (!isInstanceOf([Data], data)) {
        throw new Error(`Data.join expects an array of any of [Data, Uint8Array, ArrayBuffer, Array]. (got ${dataArray}`)
      }

      return data.length
    }).reduce((length1, length2) => length1 + length2, 0);

    const sum = new Data(length)
    dataArray.reduce((offset, data) => {
      sum.set(data, offset)
      return offset + data.length
    }, 0)
    return sum
  }

  getUint8Array() {
    return this.uint8Array
  }

  getDataView() {
    return this.dataView
  }

  createArrayBuffer() {
    return new Uint8Array(this.getUint8Array()).buffer
  }

  copy() {
    return new Data(this.createArrayBuffer())
  }

  slice(begin, end = this.getUint8Array().length) {
    if (begin < 0 || begin > this.getUint8Array().length) throw new Error("begin is out of range.")
    if (end < 0 || end > this.getUint8Array().length) throw new Error("end is out of range.")
    return new Data(this.getUint8Array().buffer.slice(this.getUint8Array().byteOffset + begin, this.getUint8Array().byteOffset + end))
  }

  get(index) {
    return this.getDataView().getUint8(index)
  }

  set(data, offset) {
    if ((data.length || data.byteLength || 0) === 0) return
    if (offset < 0 || offset >= this.getUint8Array().length) {
      throw new Error(`Offset out of range. (got ${offset})`)
    }
    if (offset + (data.length || data.byteLength || 0) > this.getUint8Array().length) {
      throw new Error("Data buffer out of range.")
    }

    if (isInstanceOf(Array, data)) {
      this.getUint8Array().set(data, offset)
    } else if (isInstanceOf(Data, data)) {
      this.getUint8Array().set(data.getUint8Array(), offset)
    } else {
      this.getUint8Array().set(new Data(data).getUint8Array(), offset)
    }
  }

  equals(rhs) {
    if (this.length != rhs.length) return false;
    for (let i = 0; i < this.length; ++i) {
      if (this.get(i) !== rhs.get(i)) return false;
    }
    return true;
  }

  static getEncodedBase64Length(dataLength) {
      return 4 * Math.ceil(dataLength / 3);
  }

  static fromBase64(string) {
    if (typeof string !== "string") {
      throw new Error(`Data.fromBase64 expects a string. (got ${string})`)
    }

    if (this.uint8Array) {
      throw new Error("Data.fromBase64 must be called in a static context")
    }

    const padding = string.length % 4 > 0 ? 4 - string.length % 4 : 0
    return new Data(base64.toByteArray(string.padEnd(string.length + padding, "=")))
  }

  toBase64() {
    return base64.fromByteArray(this.getUint8Array())
  }

  static fromBase64URL(base64url) {
    if (typeof base64url !== "string") {
      throw new Error(`Data.fromBase64URL expects a string. (got ${base64url})`)
    }

    const base64 = base64url.replace(/_/g, "/").replace(/-/g, "+")
    return this.fromBase64(base64)
  }

  toBase64URL() {
    return this.toBase64().replace(/\//g, "_").replace(/\+/g, "-")
  }

  static fromUTF8(string) {
    if (typeof string !== "string") {
      throw new Error(`Data.fromUTF8 expects a string. (got ${string})`)
    }

    if (this.uint8Array) {
      throw new Error("Data.fromUTF8 must be called in a static context")
    }

    return new Data(new TextEncoder().encode(string));
  }

  toUTF8() {
    const decoder = new TextDecoder()
    return decoder.decode(this.getUint8Array())
  }

  static fromHex(string) {    
    if (this.uint8Array) {
      throw new Error("Data.fromHex must be called in a static context")
    }

    if (!string.match(/^[0-9a-fA-F]+$/)) {
      throw new Error(`Invalid hex. (${string})`)
    }

    if (string.length > 0) {
      //return new Data(new Uint8Array(string.match(/[\da-fA-F]{2}/gi).map(h => parseInt(h, 16))))
      const paddedString = string.padStart(string.length + string.length % 2, "0");
      return new Data(new Uint8Array(paddedString.match(/[0-9a-fA-F]{2}/g).map(h => parseInt(h, 16))));
    } else {
      return new Data(0)
    }
  }

  toHex() {
    return Array.prototype.map.call(this.getUint8Array(), x => ("00" + x.toString(16)).slice(-2)).join("")
  }

}
