type PlistValue = null | boolean | number | string | PlistArray | PlistDictionary;
interface PlistArray extends Array<PlistValue> {}
interface PlistDictionary { [key: string]: PlistValue }

const MAX_OBJECTS = 100_000;
const MAX_COLLECTION_ITEMS = 10_000;
const MAX_STRING_BYTES = 1024 * 1024;
const MAX_DEPTH = 32;

function fail(message: string): never {
  throw new Error(message);
}

function byteAt(value: Buffer, offset: number): number {
  const byte = value[offset];
  if (byte === undefined) fail("binary plist offset is outside the input");
  return byte;
}

function readUnsigned(value: Buffer, offset: number, bytes: number): number {
  if (!Number.isInteger(offset) || !Number.isInteger(bytes) || bytes < 1 || bytes > 8 || offset < 0 || offset + bytes > value.length) {
    fail("binary plist integer is outside the input");
  }
  let result = 0n;
  for (let index = 0; index < bytes; index += 1) result = (result << 8n) | BigInt(byteAt(value, offset + index));
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) fail("binary plist integer exceeds the safe range");
  return Number(result);
}

function utf16BigEndian(value: Buffer, offset: number, bytes: number): string {
  if (offset < 0 || bytes < 0 || offset + bytes > value.length || bytes % 2 !== 0) fail("binary plist UTF-16 string is outside the input");
  const littleEndian = Buffer.allocUnsafe(bytes);
  for (let index = 0; index < bytes; index += 2) {
    littleEndian[index] = byteAt(value, offset + index + 1);
    littleEndian[index + 1] = byteAt(value, offset + index);
  }
  return littleEndian.toString("utf16le");
}

class BinaryPlistParser {
  readonly #value: Buffer;
  readonly #objectReferenceBytes: number;
  readonly #objectOffsets: number[];
  readonly #objectRegionEnd: number;
  readonly #cache = new Map<number, PlistValue>();
  readonly #active = new Set<number>();

  constructor(value: Buffer) {
    if (value.length < 40 || value.subarray(0, 8).toString("ascii") !== "bplist00") fail("binary plist header is invalid");
    this.#value = value;
    const trailer = value.length - 32;
    const offsetBytes = byteAt(value, trailer + 6);
    this.#objectReferenceBytes = byteAt(value, trailer + 7);
    if (offsetBytes < 1 || offsetBytes > 8 || this.#objectReferenceBytes < 1 || this.#objectReferenceBytes > 8) {
      fail("binary plist integer widths are invalid");
    }
    const objectCount = readUnsigned(value, trailer + 8, 8);
    const rootObject = readUnsigned(value, trailer + 16, 8);
    const offsetTable = readUnsigned(value, trailer + 24, 8);
    if (objectCount < 1 || objectCount > MAX_OBJECTS) fail("binary plist object count exceeds the safety limit");
    if (rootObject >= objectCount) fail("binary plist root object is invalid");
    if (offsetTable < 8 || offsetTable > trailer || objectCount * offsetBytes > trailer - offsetTable) {
      fail("binary plist offset table is invalid");
    }
    this.#objectRegionEnd = offsetTable;
    this.#objectOffsets = Array.from({ length: objectCount }, (_, index) => {
      const offset = readUnsigned(value, offsetTable + index * offsetBytes, offsetBytes);
      if (offset < 8 || offset >= offsetTable) fail("binary plist object offset is invalid");
      return offset;
    });
    this.rootObject = rootObject;
  }

  readonly rootObject: number;

  #length(info: number, cursor: number): { length: number; cursor: number } {
    if (info !== 0x0f) return { length: info, cursor };
    const marker = byteAt(this.#value, cursor);
    if (marker >> 4 !== 0x01) fail("binary plist extended length is not an integer");
    const bytes = 2 ** (marker & 0x0f);
    if (bytes > 8 || cursor + 1 + bytes > this.#objectRegionEnd) fail("binary plist extended length exceeds the safe range");
    return { length: readUnsigned(this.#value, cursor + 1, bytes), cursor: cursor + 1 + bytes };
  }

  #reference(offset: number): number {
    const reference = readUnsigned(this.#value, offset, this.#objectReferenceBytes);
    if (reference >= this.#objectOffsets.length) fail("binary plist object reference is invalid");
    return reference;
  }

  parse(index = this.rootObject, depth = 0): PlistValue {
    if (depth > MAX_DEPTH) fail("binary plist nesting exceeds the safety limit");
    if (this.#cache.has(index)) return this.#cache.get(index)!;
    if (this.#active.has(index)) fail("binary plist contains an object cycle");
    const offset = this.#objectOffsets[index];
    if (offset === undefined) fail("binary plist object index is invalid");
    this.#active.add(index);
    try {
      const marker = byteAt(this.#value, offset);
      const type = marker >> 4;
      const info = marker & 0x0f;
      let result: PlistValue;
      if (type === 0x00) {
        if (info === 0x00) result = null;
        else if (info === 0x08) result = false;
        else if (info === 0x09) result = true;
        else fail("binary plist simple object is unsupported");
      } else if (type === 0x01 || type === 0x08) {
        const bytes = type === 0x01 ? 2 ** info : info + 1;
        if (offset + 1 + bytes > this.#objectRegionEnd) fail("binary plist integer is outside the object table");
        result = readUnsigned(this.#value, offset + 1, bytes);
      } else if (type === 0x02) {
        const bytes = 2 ** info;
        if (offset + 1 + bytes > this.#objectRegionEnd) fail("binary plist real is outside the input");
        if (bytes === 4) result = this.#value.readFloatBE(offset + 1);
        else if (bytes === 8) result = this.#value.readDoubleBE(offset + 1);
        else fail("binary plist real width is unsupported");
      } else if (type === 0x03) {
        if (info !== 0x03 || offset + 9 > this.#objectRegionEnd) fail("binary plist date is invalid");
        result = this.#value.readDoubleBE(offset + 1);
      } else if (type === 0x04) {
        const measured = this.#length(info, offset + 1);
        if (measured.length > MAX_STRING_BYTES || measured.cursor + measured.length > this.#objectRegionEnd) fail("binary plist data exceeds the safety limit");
        result = `<data:${measured.length}>`;
      } else if (type === 0x05 || type === 0x06 || type === 0x07) {
        const measured = this.#length(info, offset + 1);
        const bytes = type === 0x06 ? measured.length * 2 : measured.length;
        if (bytes > MAX_STRING_BYTES || measured.cursor + bytes > this.#objectRegionEnd) fail("binary plist string exceeds the safety limit");
        if (type === 0x05) result = this.#value.subarray(measured.cursor, measured.cursor + bytes).toString("latin1");
        else if (type === 0x06) result = utf16BigEndian(this.#value, measured.cursor, bytes);
        else result = this.#value.subarray(measured.cursor, measured.cursor + bytes).toString("utf8");
      } else if (type === 0x0a || type === 0x0c) {
        const measured = this.#length(info, offset + 1);
        if (measured.length > MAX_COLLECTION_ITEMS || measured.cursor + measured.length * this.#objectReferenceBytes > this.#objectRegionEnd) {
          fail("binary plist collection exceeds the safety limit");
        }
        result = Array.from({ length: measured.length }, (_, itemIndex) => {
          const reference = this.#reference(measured.cursor + itemIndex * this.#objectReferenceBytes);
          return this.parse(reference, depth + 1);
        });
      } else if (type === 0x0d) {
        const measured = this.#length(info, offset + 1);
        const referencesBytes = measured.length * this.#objectReferenceBytes;
        if (measured.length > MAX_COLLECTION_ITEMS || measured.cursor + referencesBytes * 2 > this.#objectRegionEnd) {
          fail("binary plist dictionary exceeds the safety limit");
        }
        const dictionary: PlistDictionary = Object.create(null) as PlistDictionary;
        for (let itemIndex = 0; itemIndex < measured.length; itemIndex += 1) {
          const keyReference = this.#reference(measured.cursor + itemIndex * this.#objectReferenceBytes);
          const valueReference = this.#reference(measured.cursor + referencesBytes + itemIndex * this.#objectReferenceBytes);
          const key = this.parse(keyReference, depth + 1);
          if (typeof key !== "string" || Object.hasOwn(dictionary, key)) fail("binary plist dictionary key is invalid");
          dictionary[key] = this.parse(valueReference, depth + 1);
        }
        result = dictionary;
      } else fail("binary plist object type is unsupported");
      this.#cache.set(index, result);
      return result;
    } finally {
      this.#active.delete(index);
    }
  }
}

export function binaryPlistSearchText(value: Buffer, maxBytes: number): { text: string; truncated: boolean } {
  const root = new BinaryPlistParser(value).parse();
  const lines: string[] = [];
  let bytes = 0;
  let truncated = false;
  const add = (line: string): void => {
    if (truncated) return;
    const size = Buffer.byteLength(line) + 1;
    if (bytes + size > maxBytes) {
      truncated = true;
      return;
    }
    lines.push(line);
    bytes += size;
  };
  const visit = (item: PlistValue, depth: number): void => {
    if (truncated || depth > MAX_DEPTH) return;
    if (item === null) add("<null/>");
    else if (typeof item === "boolean") add(item ? "<true/>" : "<false/>");
    else if (typeof item === "number") add(String(item));
    else if (typeof item === "string") add(item);
    else if (Array.isArray(item)) for (const value of item) visit(value, depth + 1);
    else for (const [key, value] of Object.entries(item)) {
      add(key);
      visit(value, depth + 1);
    }
  };
  visit(root, 0);
  return { text: lines.join("\n"), truncated };
}
