import { AsnConvert, AsnUtf8StringConverter, OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { hex, isBufferSource } from "@peculiar/utils";
import { hexOptions } from "./utils";
import { AsnData } from "./asn_data";
import { Name } from "./name";
import { OidSerializer, TextObject } from "./text_converter";
import type { ParseOptions } from "./types";
import { selfProducedParseOptions } from "./utils";

const ERR_GN_CONSTRUCTOR = "Cannot initialize GeneralName from ASN.1 data.";
const ERR_GN_STRING_FORMAT = `${ERR_GN_CONSTRUCTOR} Unsupported string format in use.`;
const ERR_GUID = `${ERR_GN_CONSTRUCTOR} Value doesn't match to GUID regular expression.`;

const GUID_REGEX = /^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{4})-?([0-9a-f]{12})$/i;

const id_GUID = "1.3.6.1.4.1.311.25.1";
const id_UPN = "1.3.6.1.4.1.311.20.2.3";

export interface JsonGeneralName {
  type: GeneralNameType;
  value: string;
}

export const DNS = "dns";
export const DN = "dn";
export const EMAIL = "email";
export const IP = "ip";
export const URL = "url";
export const GUID = "guid";
export const UPN = "upn";
export const REGISTERED_ID = "id";

export type GeneralNameType = typeof DNS | typeof DN | typeof EMAIL | typeof GUID | typeof IP | typeof URL | typeof UPN | typeof REGISTERED_ID;

/**
 * Canonicalizes a DNS host name for security-sensitive comparison.
 * Converts IDN (U-labels) into punycode A-labels, removes the trailing
 * root dot from fully-qualified names and lowercases ASCII letters.
 */
function canonicalizeDnsName(name: string): string {
  let res = name;
  // Remove the root label (trailing dot) from fully-qualified names
  while (res.endsWith(".")) {
    res = res.slice(0, -1);
  }
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(res)) {
    // Convert IDN labels to punycode using the WHATWG URL host parser,
    // which is available both in browsers and Node.js
    try {
      // NOTE: `globalThis.URL` is used because the module scope declares
      // its own `URL` constant for the GeneralName type
      const host = new globalThis.URL(`http://${res}`).hostname;
      if (host) {
        res = host;
      }
    } catch {
      // keep the original value if it cannot be parsed as a host name
    }
  }

  return res.toLowerCase();
}

/**
 * Canonicalizes an email address (rfc822Name) for security-sensitive
 * comparison. The mailbox is compared case-insensitively and the domain
 * part is canonicalized as a DNS host name.
 */
function canonicalizeEmail(email: string): string {
  const atIndex = email.lastIndexOf("@");
  if (atIndex === -1) {
    return email.toLowerCase();
  }
  const localPart = email.slice(0, atIndex).toLowerCase();
  const domain = canonicalizeDnsName(email.slice(atIndex + 1));

  return `${localPart}@${domain}`;
}

/**
 * Parses an IPv4 address in dotted-decimal notation into 4 bytes.
 * Returns `null` if the value is not a valid IPv4 address.
 */
function parseIPv4Address(ip: string): Uint8Array | null {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    // Reject leading zeros to avoid octal-like ambiguity
    if (part.length > 1 && part.startsWith("0")) {
      return null;
    }
    const num = Number(part);
    if (num > 255) {
      return null;
    }
    bytes[i] = num;
  }

  return bytes;
}

/**
 * Parses a single 16-bit IPv6 group. Returns `null` if the group is invalid.
 */
function parseIPv6Group(group: string): number | null {
  if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
    return null;
  }

  return parseInt(group, 16);
}

/**
 * Parses an IPv6 address (including `::` compression and embedded IPv4
 * notation) into 16 bytes. Returns `null` if the value is not a valid
 * IPv6 address.
 */
function parseIPv6Address(addr: string): Uint8Array | null {
  let rest = addr;
  // Embedded IPv4 notation (eg "::ffff:192.168.0.1") counts as two 16-bit groups
  const lastColonIndex = rest.lastIndexOf(":");
  const lastPart = lastColonIndex === -1 ? rest : rest.slice(lastColonIndex + 1);
  if (lastPart.includes(".")) {
    if (lastColonIndex === -1) {
      return null;
    }
    const v4 = parseIPv4Address(lastPart);
    if (!v4) {
      return null;
    }
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    rest = `${rest.slice(0, lastColonIndex)}:${hi}:${lo}`;
  }
  const halves = rest.split("::");
  if (halves.length > 2) {
    return null;
  }
  const head: number[] = [];
  if (halves[0] !== "") {
    for (const group of halves[0].split(":")) {
      const num = parseIPv6Group(group);
      if (num === null) {
        return null;
      }
      head.push(num);
    }
  }
  const tail: number[] = [];
  if (halves.length === 2 && halves[1] !== "") {
    for (const group of halves[1].split(":")) {
      const num = parseIPv6Group(group);
      if (num === null) {
        return null;
      }
      tail.push(num);
    }
  }
  const count = head.length + tail.length;
  if (halves.length === 1) {
    // Without "::" the address must be in the full form
    if (count !== 8) {
      return null;
    }
  } else if (count >= 8) {
    // "::" must compress at least one group of zeros
    return null;
  }
  const groups = [...head, ...Array.from({ length: 8 - count }, () => 0), ...tail];
  if (groups.length !== 8) {
    return null;
  }
  const bytes = new Uint8Array(16);
  groups.forEach((group, i) => {
    bytes[i * 2] = group >> 8;
    bytes[i * 2 + 1] = group & 0xff;
  });

  return bytes;
}

/**
 * Canonicalizes an IP address for security-sensitive comparison. IPv4 and
 * IPv6 addresses are reduced to their raw byte representation so that
 * different notations of the same address compare equal. Values that
 * cannot be parsed are left untouched.
 */
function canonicalizeIpAddress(ip: string): string {
  let addr = ip;
  let suffix = "";
  // CIDR notation (eg from name constraints)
  const slashIndex = addr.indexOf("/");
  if (slashIndex !== -1) {
    suffix = addr.slice(slashIndex);
    addr = addr.slice(0, slashIndex);
  }
  let zone = "";
  const percentIndex = addr.indexOf("%");
  if (percentIndex !== -1) {
    zone = addr.slice(percentIndex);
    addr = addr.slice(0, percentIndex);
  }
  const v4 = parseIPv4Address(addr);
  if (v4) {
    return `${hex.encode(v4)}${zone}${suffix}`;
  }
  const v6 = parseIPv6Address(addr);
  if (v6) {
    return `${hex.encode(v6)}${zone}${suffix}`;
  }

  return ip;
}

/**
 * Canonicalizes a URI for security-sensitive comparison. The scheme and
 * host name are lowercased, IDN hosts are converted to punycode, the
 * trailing root dot is removed from the host and default ports are
 * dropped. URIs that cannot be parsed are left untouched.
 */
function canonicalizeUri(uri: string): string {
  let url: globalThis.URL;
  try {
    // NOTE: `globalThis.URL` is used because the module scope declares
    // its own `URL` constant for the GeneralName type
    url = new globalThis.URL(uri);
  } catch {
    return uri;
  }
  const scheme = url.protocol.toLowerCase();
  if (!uri.slice(url.protocol.length).startsWith("//")) {
    // URIs without an authority component (eg "urn:*")
    return `${scheme}${url.pathname}${url.search}${url.hash}`;
  }
  let host = url.hostname;
  // Remove the root label (trailing dot) from fully-qualified host names
  while (host.endsWith(".")) {
    host = host.slice(0, -1);
  }
  const port = url.port ? `:${url.port}` : "";
  const auth = url.username ? `${url.username}${url.password ? `:${url.password}` : ""}@` : "";

  return `${scheme}//${auth}${host}${port}${url.pathname}${url.search}${url.hash}`;
}

/**
 * Computes the canonical form of a GeneralName value of the given type.
 * Names of different types never share a canonical form.
 */
function canonicalizeGeneralNameValue(type: GeneralNameType, value: string): string {
  switch (type) {
    case DNS:
      return canonicalizeDnsName(value);
    case EMAIL:
      return canonicalizeEmail(value);
    case IP:
      return canonicalizeIpAddress(value);
    case URL:
      return canonicalizeUri(value);
    case GUID:
      return value.toLowerCase();
    default:
      // dn, upn and id are compared by their exact value
      return value;
  }
}

/**
 * Represents ASN.1 type of GeneralName.
 *
 * This class doesn't support no standard string format is
 * defined for otherName, X.400 name, EDI party name, or any other type of names.
 */
export class GeneralName extends AsnData<asn1X509.GeneralName> {
  /**
   * Type of the storing value
   */
  public type!: GeneralNameType;
  /**
   * Text representation of ASN.1 GeneralName
   */
  public value!: string;

  public constructor(type: GeneralNameType, value: string);
  public constructor(asn: asn1X509.GeneralName, options?: ParseOptions);
  public constructor(raw: BufferSource, options?: ParseOptions);
  public constructor(...args: any[]) {
    let name: asn1X509.GeneralName;
    let options: ParseOptions | undefined;
    // NOTE: the BufferSource check comes first because `new GeneralName(raw, options)`
    // also has two arguments and must not fall into the `(type, value)` branch
    if (isBufferSource(args[0])) {
      // raw: BufferSource, options?: ParseOptions
      options = args[1];
      name = AsnConvert.parse(args[0], asn1X509.GeneralName, options);
    } else if (typeof args[0] === "string") {
      // type: GeneralNameType, value: string
      options = selfProducedParseOptions;
      switch (args[0] as GeneralNameType) {
        case DN: {
          const derName = new Name(args[1]).toArrayBuffer();
          const asnName = AsnConvert.parse(derName, asn1X509.Name, selfProducedParseOptions);
          name = new asn1X509.GeneralName({ directoryName: asnName });
          break;
        }
        case DNS:
          name = new asn1X509.GeneralName({ dNSName: args[1] });
          break;
        case EMAIL:
          name = new asn1X509.GeneralName({ rfc822Name: args[1] });
          break;
        case GUID: {
          const matches = new RegExp(GUID_REGEX, "i").exec(args[1]);
          if (!matches) {
            throw new Error("Cannot parse GUID value. Value doesn't match to regular expression");
          }
          const guidHex = matches
            .slice(1)
            .map((o, i) => {
              if (i < 3) {
                return hex.encode(new Uint8Array(hex.decode(o, hexOptions)).reverse());
              }

              return o;
            })
            .join("");

          name = new asn1X509.GeneralName({
            otherName: new asn1X509.OtherName({
              typeId: id_GUID,
              value: AsnConvert.serialize(new OctetString(hex.decode(guidHex, hexOptions))),
            }),
          });
          break;
        }
        case IP:
          name = new asn1X509.GeneralName({ iPAddress: args[1] });
          break;
        case REGISTERED_ID:
          name = new asn1X509.GeneralName({ registeredID: args[1] });
          break;
        case UPN: {
          name = new asn1X509.GeneralName({
            otherName: new asn1X509.OtherName({
              typeId: id_UPN,
              value: AsnConvert.serialize(AsnUtf8StringConverter.toASN(args[1])),
            }),
          });
          break;
        }
        case URL:
          name = new asn1X509.GeneralName({ uniformResourceIdentifier: args[1] });
          break;
        default:
          throw new Error("Cannot create GeneralName. Unsupported type of the name");
      }
    } else {
      // asn: asn1X509.GeneralName, options?: ParseOptions
      name = args[0];
      options = args[1] ?? selfProducedParseOptions;
    }
    super(name, options);
  }

  /**
   * Occurs on instance initialization
   * @param asn
   *
   * @throws Throws error if ASN.1 GeneralName contains
   * unsupported value (eg otherName, X400 address, EDI party name)
   */
  protected onInit(asn: asn1X509.GeneralName): void {
    if (asn.dNSName != undefined) {
      this.type = DNS;
      this.value = asn.dNSName;
    } else if (asn.rfc822Name != undefined) {
      this.type = EMAIL;
      this.value = asn.rfc822Name;
    } else if (asn.iPAddress != undefined) {
      this.type = IP;
      this.value = asn.iPAddress;
    } else if (asn.uniformResourceIdentifier != undefined) {
      this.type = URL;
      this.value = asn.uniformResourceIdentifier;
    } else if (asn.registeredID != undefined) {
      this.type = REGISTERED_ID;
      this.value = asn.registeredID;
    } else if (asn.directoryName != undefined) {
      this.type = DN;
      this.value = new Name(asn.directoryName).toString();
    } else if (asn.otherName != undefined) {
      if (asn.otherName.typeId === id_GUID) {
        this.type = GUID;
        const guid = AsnConvert.parse(asn.otherName.value, OctetString, this.parseOptions);
        const matches = new RegExp(GUID_REGEX, "i").exec(hex.encode(guid));
        if (!matches) {
          throw new Error(ERR_GUID);
        }
        this.value = matches
          .slice(1)
          .map((o, i) => {
            if (i < 3) {
              return hex.encode(new Uint8Array(hex.decode(o, hexOptions)).reverse());
            }

            return o;
          })
          .join("-");
      } else if (asn.otherName.typeId === id_UPN) {
        this.type = UPN;
        this.value = AsnConvert.parse(asn.otherName.value, asn1X509.DirectoryString, this.parseOptions).toString();
      } else {
        throw new Error(ERR_GN_STRING_FORMAT);
      }
    } else {
      throw new Error(ERR_GN_STRING_FORMAT);
    }
  }

  /**
   * Returns the canonical form of the name value used for security-sensitive
   * comparison. The raw {@link GeneralName.value|value} is preserved unchanged;
   * the canonical form normalizes the value according to its {@link GeneralName.type|type}
   * (eg DNS names are lowercased, IDN names are converted to punycode, the
   * trailing root dot is removed, IP addresses are reduced to raw bytes and
   * email addresses are compared case-insensitively).
   */
  public get canonicalValue(): string {
    return canonicalizeGeneralNameValue(this.type, this.value);
  }

  /**
   * Compares this name with another GeneralName for certificate matching.
   * Names of different types are never equal, even if their text
   * representations look the same (eg a DNS name and a UPN). Values are
   * compared by their {@link GeneralName.canonicalValue|canonical form}.
   * @param other GeneralName to compare with
   * @returns `true` if both names identify the same subject
   */
  public matches(other: GeneralName): boolean {
    if (this.type !== other.type) {
      return false;
    }

    return this.canonicalValue === other.canonicalValue;
  }

  public toJSON(): JsonGeneralName {
    return {
      type: this.type,
      value: this.value,
    };
  }

  public override toTextObject(): TextObject {
    let type: string;
    switch (this.type) {
      case DN:
      case DNS:
      case GUID:
      case IP:
      case REGISTERED_ID:
      case UPN:
      case URL:
        type = this.type.toUpperCase();
        break;
      case EMAIL:
        type = "Email";
        break;
      default:
        throw new Error("Unsupported GeneralName type");
    }

    let value = this.value;
    if (this.type === REGISTERED_ID) {
      value = OidSerializer.toString(value);
    }

    return new TextObject(type, undefined, value);
  }
}

export type JsonGeneralNames = JsonGeneralName[];

export class GeneralNames extends AsnData<asn1X509.GeneralNames> {
  public static override NAME = "GeneralNames";

  public items!: readonly GeneralName[];

  constructor(json: JsonGeneralNames);
  constructor(asn: asn1X509.GeneralNames | asn1X509.GeneralName[]);
  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   */
  constructor(raw: BufferSource, options?: ParseOptions);
  constructor(params: JsonGeneralNames | asn1X509.GeneralNames | asn1X509.GeneralName[] | BufferSource, options?: ParseOptions) {
    let names: asn1X509.GeneralNames;
    // Only the raw overload takes DER from the caller; the others are built here
    let stored = selfProducedParseOptions;
    if (params instanceof asn1X509.GeneralNames) {
      // asn1X509.GeneralNames
      names = params;
    } else if (Array.isArray(params)) {
      // JsonGeneralNames[] | asn1X509.GeneralName[]
      const items: asn1X509.GeneralName[] = [];

      for (const name of params) {
        if (name instanceof asn1X509.GeneralName) {
          items.push(name);
        } else {
          const asnName = AsnConvert.parse(new GeneralName(name.type, name.value).rawData, asn1X509.GeneralName, selfProducedParseOptions);
          items.push(asnName);
        }
      }

      names = new asn1X509.GeneralNames(items);
    } else if (isBufferSource(params)) {
      names = AsnConvert.parse(params, asn1X509.GeneralNames, options);
      stored = options ?? {};
    } else {
      throw new Error("Cannot initialize GeneralNames. Incorrect incoming arguments");
    }

    super(names, stored);
  }

  protected onInit(asn: asn1X509.GeneralNames): void {
    const items: GeneralName[] = [];
    for (const asnName of asn) {
      let name: GeneralName | null = null;
      try {
        name = new GeneralName(asnName, this.parseOptions);
      } catch {
        // skip unsupported ASN.1 GeneralName
        continue;
      }
      items.push(name);
    }

    this.items = items;
  }

  /**
   * Compares this list of names with another one for certificate matching.
   * Both lists are compared as unordered sets: every name must have a
   * matching counterpart on the other side, regardless of the order in
   * which the names appear in the extension.
   * @param other GeneralNames to compare with
   * @returns `true` if both lists contain the same names
   */
  public matches(other: GeneralNames): boolean {
    if (this.items.length !== other.items.length) {
      return false;
    }
    const matched = new Set<number>();
    for (const item of this.items) {
      const index = other.items.findIndex((otherItem, otherIndex) => !matched.has(otherIndex) && item.matches(otherItem));
      if (index === -1) {
        return false;
      }
      matched.add(index);
    }

    return true;
  }

  public toJSON(): JsonGeneralNames {
    return this.items.map((o) => o.toJSON());
  }

  public override toTextObject(): TextObject {
    const res = super.toTextObjectEmpty();

    for (const name of this.items) {
      const nameObj = name.toTextObject();
      let field = res[nameObj[TextObject.NAME]];
      if (!Array.isArray(field)) {
        field = [];
        res[nameObj[TextObject.NAME]] = field;
      }

      field.push(nameObj);
    }

    return res;
  }
}
