import { base64, isBufferSource, toArrayBuffer } from "@peculiar/utils";

const rPaddingTag = "-{5}";
const rEolChars = "\\n";
const rNameTag = `[^${rEolChars}]+`;
const rBeginTag = `${rPaddingTag}BEGIN (${rNameTag}(?=${rPaddingTag}))${rPaddingTag}`;
const rEndTag = `${rPaddingTag}END \\1${rPaddingTag}`;
const rEolGroup = "\\n";
const rHeaderKey = `[^:${rEolChars}]+`;
const rHeaderValue = `(?:[^${rEolChars}]+${rEolGroup}(?: +[^${rEolChars}]+${rEolGroup})*)`;
const rBase64Chars = "[a-zA-Z0-9=+/]+";
const rBase64 = `(?:${rBase64Chars}${rEolGroup})+`;
const rPem = `${rBeginTag}${rEolGroup}(?:((?:${rHeaderKey}: ${rHeaderValue})+))?${rEolGroup}?(${rBase64})${rEndTag}`;
const rEolPattern = new RegExp(`[${rEolChars}]+`, "g");

export interface PemHeader {
  key: string;
  value: string;
}

/**
 * Represents a PEM block found in a bundle, with its position in the inventory
 */
export interface PemInventoryBlock extends PemStruct {
  /**
   * Zero-based position of the block in the bundle
   */
  index: number;
  /**
   * Offset of the `-----BEGIN` line in the normalized (LF) PEM text
   */
  offset: number;
}

/**
 * Kind of dangling content found outside of valid PEM blocks
 */
export type PemDanglingKind =
  /** Text outside of any PEM block */
  | "text"
  /** `BEGIN` line without any matching `END` line */
  | "truncated"
  /** `BEGIN` and `END` lines with different types */
  | "mismatched-end"
  /** `BEGIN`/`END` pair whose body is not a valid PEM block */
  | "malformed";

/**
 * Represents content of a PEM bundle which is not a valid PEM block
 */
export interface PemDanglingContent {
  /**
   * Kind of the dangling content
   */
  kind: PemDanglingKind;
  /**
   * Offset of the content in the normalized (LF) PEM text
   */
  offset: number;
  /**
   * The dangling text
   */
  text: string;
  /**
   * Type of the `BEGIN` line. Present for `truncated`, `mismatched-end` and `malformed` kinds
   */
  type?: string;
  /**
   * Type of the mismatched `END` line. Present for `mismatched-end` kind only
   */
  endType?: string;
}

/**
 * Type of a PEM bundle issue
 */
export type PemIssueType =
  /** Two or more blocks share the same type and data */
  | "duplicate"
  /** Block type is not in the list of known types */
  | "unknown-type"
  /** Content which is not a valid PEM block */
  | "dangling";

/**
 * Represents a conclusion about a PEM bundle
 */
export interface PemIssue {
  /**
   * Type of the issue
   */
  type: PemIssueType;
  /**
   * Human readable conclusion
   */
  message: string;
  /**
   * Indexes of the inventory blocks involved in the issue
   */
  blocks?: number[];
}

/**
 * Represents a complete inventory of a PEM bundle
 */
export interface PemInventory {
  /**
   * All valid PEM blocks in the order they appear in the bundle.
   * Matches the result of {@link PemConverter.decodeWithHeaders}
   */
  blocks: PemInventoryBlock[];
  /**
   * Content which is not a valid PEM block (stray text, truncated or malformed blocks)
   */
  dangling: PemDanglingContent[];
  /**
   * Conclusions about duplicates, unknown types and dangling content
   */
  issues: PemIssue[];
  /**
   * `true` if the bundle contains valid blocks only and no issues were found
   */
  ok: boolean;
}

/**
 * Options for {@link PemConverter.inspect}
 */
export interface PemInspectOptions {
  /**
   * List of known PEM block types. Blocks with other types are reported as `unknown-type` issues.
   * Defaults to the tags known to {@link PemConverter}
   */
  knownTypes?: string[];
}

/**
 * Represents PEM structure
 */
export interface PemStruct {
  /**
   * Type
   */
  type: string;
  /**
   * Headers
   */
  headers: PemHeader[];

  /**
   * Decoded message data
   */
  rawData: ArrayBuffer;
}

type AtLeast<T, K extends keyof T> = Partial<T> & Pick<T, K>;

export type PemStructEncodeParams = AtLeast<PemStruct, "type" | "rawData">;

/**
 * Represents PEM Converter.
 */
export class PemConverter {
  public static CertificateTag = "CERTIFICATE";
  public static CrlTag = "CRL";
  public static CertificateRequestTag = "CERTIFICATE REQUEST";
  public static PublicKeyTag = "PUBLIC KEY";
  public static PrivateKeyTag = "PRIVATE KEY";

  /**
   * Default list of known PEM block types used by {@link PemConverter.inspect}
   */
  public static knownTypes: string[] = [PemConverter.CertificateTag, PemConverter.CrlTag, PemConverter.CertificateRequestTag, PemConverter.PublicKeyTag, PemConverter.PrivateKeyTag];

  public static isPem(data: any): data is string {
    return typeof data === "string" && new RegExp(rPem, "g").test(data.replace(/\r/g, ""));
  }

  public static decodeWithHeaders(pem: string): PemStruct[] {
    pem = pem.replace(/\r/g, ""); // CRLF -> LF
    const pattern = new RegExp(rPem, "g");

    const res: PemStruct[] = [];

    let matches: RegExpExecArray | null = null;
    // eslint-disable-next-line no-cond-assign
    while ((matches = pattern.exec(pem))) {
      // prepare pem encoded message
      const base64Text = matches[3].replace(rEolPattern, "");

      const pemStruct: PemStruct = {
        type: matches[1],
        headers: [],
        rawData: toArrayBuffer(base64.decode(base64Text)),
      };

      // read headers
      const headersString = matches[2];
      if (headersString) {
        const headers = headersString.split(new RegExp(rEolGroup, "g"));
        let lastHeader: PemHeader | null = null;
        for (const header of headers) {
          const [key, value] = header.split(/:(.*)/);
          if (value === undefined) {
            // value
            if (!lastHeader) {
              throw new Error("Cannot parse PEM string. Incorrect header value");
            }
            lastHeader.value += key.trim();
          } else {
            // key and value
            if (lastHeader) {
              pemStruct.headers.push(lastHeader);
            }
            lastHeader = {
              key,
              value: value.trim(),
            };
          }
        }
        // add last header
        if (lastHeader) {
          pemStruct.headers.push(lastHeader);
        }
      }

      res.push(pemStruct);
    }

    return res;
  }

  /**
   * Inspects a PEM bundle and returns a complete inventory of its blocks
   * along with conclusions about duplicates, unknown types and dangling content
   * (stray text, truncated or malformed blocks).
   *
   * The returned `blocks` list contains exactly the same objects, in the same order,
   * as {@link PemConverter.decodeWithHeaders}, so an auditor sees the same objects
   * as a loader.
   * @param pem message in PEM format
   * @param options inspection options
   */
  public static inspect(pem: string, options?: PemInspectOptions): PemInventory {
    const normalized = pem.replace(/\r/g, ""); // CRLF -> LF
    const pattern = new RegExp(rPem, "g");

    const blocks: PemInventoryBlock[] = [];
    const matchedRanges: Array<[number, number]> = [];

    let matches: RegExpExecArray | null = null;
    // eslint-disable-next-line no-cond-assign
    while ((matches = pattern.exec(normalized))) {
      const struct = this.decodeWithHeaders(matches[0])[0];
      blocks.push({
        ...struct,
        index: blocks.length,
        offset: matches.index,
      });
      matchedRanges.push([matches.index, matches.index + matches[0].length]);
    }

    // collect dangling content from the gaps between valid blocks
    const dangling: PemDanglingContent[] = [];
    let position = 0;
    for (const [start, end] of matchedRanges) {
      this.inspectGap(normalized.slice(position, start), position, dangling);
      position = end;
    }
    this.inspectGap(normalized.slice(position), position, dangling);

    // build conclusions
    const issues: PemIssue[] = [];

    const knownTypes = new Set((options?.knownTypes ?? PemConverter.knownTypes).map((type) => type.toUpperCase()));
    const blockGroups = new Map<string, number[]>();
    for (const block of blocks) {
      if (!knownTypes.has(block.type.toUpperCase())) {
        issues.push({
          type: "unknown-type",
          message: `Block #${block.index} has unknown type '${block.type}'`,
          blocks: [block.index],
        });
      }

      const key = `${block.type}:${base64.encode(block.rawData)}`;
      const group = blockGroups.get(key);
      if (group) {
        group.push(block.index);
      } else {
        blockGroups.set(key, [block.index]);
      }
    }

    for (const group of blockGroups.values()) {
      if (group.length > 1) {
        issues.push({
          type: "duplicate",
          message: `Blocks ${group.map((index) => `#${index}`).join(", ")} are duplicates of the same '${blocks[group[0]].type}' block`,
          blocks: group,
        });
      }
    }

    for (const item of dangling) {
      issues.push({
        type: "dangling",
        message: this.describeDangling(item),
      });
    }

    return {
      blocks,
      dangling,
      issues,
      ok: issues.length === 0,
    };
  }

  /**
   * Scans a gap between valid PEM blocks for dangling content
   * @param gap Text between valid PEM blocks
   * @param offset Offset of the gap in the normalized PEM text
   * @param dangling List of dangling content to append to
   */
  private static inspectGap(gap: string, offset: number, dangling: PemDanglingContent[]): void {
    const pushText = (text: string, textOffset: number): void => {
      const trimmed = text.trim();
      if (trimmed) {
        dangling.push({
          kind: "text",
          offset: textOffset + (text.length - text.trimStart().length),
          text: trimmed,
        });
      }
    };

    const beginPattern = new RegExp(rBeginTag, "g");
    const endPattern = new RegExp(`${rPaddingTag}END (${rNameTag}(?=${rPaddingTag}))${rPaddingTag}`, "g");

    let position = 0;
    let beginMatch: RegExpExecArray | null = null;
    // eslint-disable-next-line no-cond-assign
    while ((beginMatch = beginPattern.exec(gap))) {
      pushText(gap.slice(position, beginMatch.index), offset + position);

      const beginType = beginMatch[1];
      endPattern.lastIndex = beginMatch.index + beginMatch[0].length;
      const endMatch = endPattern.exec(gap);

      if (!endMatch) {
        dangling.push({
          kind: "truncated",
          offset: offset + beginMatch.index,
          text: gap.slice(beginMatch.index).trim(),
          type: beginType,
        });
        position = gap.length;
        break;
      }

      const blockText = gap.slice(beginMatch.index, endMatch.index + endMatch[0].length);
      if (endMatch[1] !== beginType) {
        dangling.push({
          kind: "mismatched-end",
          offset: offset + beginMatch.index,
          text: blockText,
          type: beginType,
          endType: endMatch[1],
        });
      } else {
        dangling.push({
          kind: "malformed",
          offset: offset + beginMatch.index,
          text: blockText,
          type: beginType,
        });
      }

      position = endMatch.index + endMatch[0].length;
      beginPattern.lastIndex = position;
    }

    pushText(gap.slice(position), offset + position);
  }

  /**
   * Creates a human readable conclusion for dangling content
   * @param item Dangling content
   */
  private static describeDangling(item: PemDanglingContent): string {
    switch (item.kind) {
      case "truncated":
        return `Dangling '${item.type}' block at offset ${item.offset}: BEGIN line has no matching END line`;
      case "mismatched-end":
        return `Dangling block at offset ${item.offset}: BEGIN '${item.type}' is closed by END '${item.endType}'`;
      case "malformed":
        return `Dangling '${item.type}' block at offset ${item.offset}: content is not a valid PEM block`;
      default:
        return `Dangling text at offset ${item.offset}: '${item.text}'`;
    }
  }

  /**
   * Decodes PEM to a list of raws
   * @param pem message in PEM format
   */
  public static decode(pem: string): ArrayBuffer[] {
    const blocks = this.decodeWithHeaders(pem);

    return blocks.map((o) => o.rawData);
  }

  /**
   * Decodes PEM and returns first item from the list
   * @param pem message in PEM format
   * @throw Throws RangeError if list of decoded items is empty
   */
  public static decodeFirst(pem: string): ArrayBuffer {
    const items = this.decode(pem);
    if (!items.length) {
      throw new RangeError("PEM string doesn't contain any objects");
    }

    return items[0];
  }

  /**
   * Encodes a list of PemStruct in PEM format
   * @param structs A list of PemStruct
   * @param tag PEM tag
   */
  public static encode(structs: PemStructEncodeParams[]): string;
  /**
   * Encodes a raw data in PEM format
   * @param rawData Raw data
   * @param tag PEM tag
   */
  public static encode(rawData: BufferSource, tag: string): string;
  /**
   * Encodes a list of raws in PEM format
   * @param raws A list of raws
   * @param tag PEM tag
   */
  public static encode(rawData: BufferSource[], tag: string): string;
  public static encode(rawData: BufferSource | BufferSource[] | PemStructEncodeParams[], tag?: string) {
    if (Array.isArray(rawData)) {
      const raws = new Array<string>();
      if (tag) {
        // encode BufferSource[]
        rawData.forEach((element) => {
          if (!isBufferSource(element)) {
            throw new TypeError("Cannot encode array of BufferSource in PEM format. Not all items of the array are BufferSource");
          }
          raws.push(
            this.encodeStruct({
              type: tag,
              rawData: toArrayBuffer(element),
            }),
          );
        });
      } else {
        // encode PemStruct[]
        rawData.forEach((element) => {
          if (!("type" in element)) {
            throw new TypeError("Cannot encode array of PemStruct in PEM format. Not all items of the array are PemStrut");
          }
          raws.push(this.encodeStruct(element));
        });
      }

      return raws.join("\n");
    } else {
      if (!tag) {
        throw new Error("Required argument 'tag' is missed");
      }

      return this.encodeStruct({
        type: tag,
        rawData: toArrayBuffer(rawData),
      });
    }
  }

  /**
   * Encodes PEMStruct in PEM block
   * @param pem PEM structure for encoding
   * @returns Returns PEM encoded block
   */
  private static encodeStruct(pem: PemStructEncodeParams): string {
    const upperCaseType = pem.type.toLocaleUpperCase();

    const res: string[] = [];
    res.push(`-----BEGIN ${upperCaseType}-----`);

    if (pem.headers?.length) {
      for (const header of pem.headers) {
        res.push(`${header.key}: ${header.value}`);
      }

      res.push(""); // blank line
    }

    const base64Text = base64.encode(pem.rawData);
    for (let i = 0; i < base64Text.length; i += 64) {
      res.push(base64Text.substring(i, i + 64));
    }

    res.push(`-----END ${upperCaseType}-----`);

    return res.join("\n");
  }
}
