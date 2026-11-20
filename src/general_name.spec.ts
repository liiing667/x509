import { describe, it, expect } from "vitest";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as asn1Schema from "@peculiar/asn1-schema";
import * as x509 from "./index";

describe("GeneralName", () => {
  describe("constructor", () => {
    const tests: {
      name: string;
      args: x509.JsonGeneralName | asn1X509.GeneralName | BufferSource;
      want?: x509.JsonGeneralName;
      wantError?: Error;
    }[] = [
      {
        name: "dn:CN=name, O=org",
        args: {
          type: "dn",
          value: "CN=name,O=org",
        },
        want: {
          type: "dn",
          value: "CN=name, O=org",
        },
      },
      {
        name: "dns:some.com",
        args: {
          type: "dns",
          value: "some.com",
        },
        want: {
          type: "dns",
          value: "some.com",
        },
      },
      {
        name: "email:some@email.com",
        args: {
          type: "email",
          value: "some@email.com",
        },
        want: {
          type: "email",
          value: "some@email.com",
        },
      },
      {
        name: "guid:33636766-dee4-4ac5-a4ae-af8380c7a655",
        args: {
          type: "guid",
          value: "33636766-DEE4-4AC5-A4AE-AF8380C7A655",
        },
        want: {
          type: "guid",
          value: "33636766-dee4-4ac5-a4ae-af8380c7a655",
        },
      },
      {
        name: "guid:incorrect",
        args: {
          type: "guid",
          value: "incorrect",
        },
        wantError: new Error("Cannot parse GUID value. Value doesn't match to regular expression"),
      },
      {
        name: "id:1.2.3.4.5.6",
        args: {
          type: "id",
          value: "1.2.3.4.5.6",
        },
        want: {
          type: "id",
          value: "1.2.3.4.5.6",
        },
      },
      {
        name: "ip:192.168.0.1",
        args: {
          type: "ip",
          value: "192.168.0.1",
        },
        want: {
          type: "ip",
          value: "192.168.0.1",
        },
      },
      {
        name: "upn:user@domain.com",
        args: {
          type: "upn",
          value: "user@domain.com",
        },
        want: {
          type: "upn",
          value: "user@domain.com",
        },
      },
      {
        name: "url:https://some.com",
        args: {
          type: "url",
          value: "https://some.com",
        },
        want: {
          type: "url",
          value: "https://some.com",
        },
      },
      {
        name: "raw:BufferSource",
        args: Buffer.from("8208736f6d652e636f6d", "hex"),
        want: {
          type: "dns",
          value: "some.com",
        },
      },
      {
        name: "asn:GeneralName",
        args: asn1Schema.AsnConvert.parse(Buffer.from("8208736f6d652e636f6d", "hex"), asn1X509.GeneralName),
        want: {
          type: "dns",
          value: "some.com",
        },
      },
    ];

    for (const t of tests) {
      it(t.name, () => {
        function create(): x509.GeneralName {
          if ("type" in t.args) {
            return new x509.GeneralName(t.args.type, t.args.value);
          }

          return new x509.GeneralName(t.args as BufferSource);
        }

        if (t.wantError) {
          expect(create).toThrow(t.wantError);
        } else {
          const obj = create().toJSON();
          expect(obj).toEqual(t.want);
        }
      });
    }
  });

  describe("toString", () => {
    const tests: {
      name: string;
      args: { type: x509.GeneralNameType; value: string };
      want: string;
    }[] = [
      {
        name: "dn:CN=name, O=org",
        args: {
          type: "dn",
          value: "CN=name,O=org",
        },
        want: "DN: CN=name, O=org",
      },
      {
        name: "dns:some.com",
        args: {
          type: "dns",
          value: "some.com",
        },
        want: "DNS: some.com",
      },
      {
        name: "email:some@email.com",
        args: {
          type: "email",
          value: "some@email.com",
        },
        want: "Email: some@email.com",
      },
      {
        name: "guid:33636766-dee4-4ac5-a4ae-af8380c7a655",
        args: {
          type: "guid",
          value: "33636766-DEE4-4AC5-A4AE-AF8380C7A655",
        },
        want: "GUID: 33636766-dee4-4ac5-a4ae-af8380c7a655",
      },
      {
        name: "id:1.2.3.4.5.6",
        args: {
          type: "id",
          value: "1.2.3.4.5.6",
        },
        want: "ID: 1.2.3.4.5.6",
      },
      {
        name: "ip:192.168.0.1",
        args: {
          type: "ip",
          value: "192.168.0.1",
        },
        want: "IP: 192.168.0.1",
      },
      {
        name: "upn:user@domain.com",
        args: {
          type: "upn",
          value: "user@domain.com",
        },
        want: "UPN: user@domain.com",
      },
      {
        name: "url:https://some.com",
        args: {
          type: "url",
          value: "https://some.com",
        },
        want: "URL: https://some.com",
      },
    ];
    for (const t of tests) {
      it(t.name, () => {
        const name = new x509.GeneralName(t.args.type, t.args.value);
        const text = name.toString("text");
        expect(text).toBe(t.want);
      });
    }
  });

  describe("canonicalValue", () => {
    it("preserves the raw value", () => {
      const name = new x509.GeneralName("dns", "Example.COM.");
      expect(name.value).toBe("Example.COM.");
      expect(name.canonicalValue).toBe("example.com");
    });

    const tests: {
      name: string;
      args: { type: x509.GeneralNameType; value: string };
      want: string;
    }[] = [
      {
        name: "dns: lowercase",
        args: { type: "dns", value: "Example.COM" },
        want: "example.com",
      },
      {
        name: "dns: trailing dot",
        args: { type: "dns", value: "example.com." },
        want: "example.com",
      },
      {
        name: "dns: IDN to punycode",
        args: { type: "dns", value: "bücher.de" },
        want: "xn--bcher-kva.de",
      },
      {
        name: "email: case-insensitive",
        args: { type: "email", value: "User@Example.COM" },
        want: "user@example.com",
      },
      {
        name: "email: IDN domain",
        args: { type: "email", value: "user@bücher.de" },
        want: "user@xn--bcher-kva.de",
      },
      {
        name: "ip: IPv4",
        args: { type: "ip", value: "192.168.0.1" },
        want: "c0a80001",
      },
      {
        name: "ip: IPv6 compressed",
        args: { type: "ip", value: "::1" },
        want: "00000000000000000000000000000001",
      },
      {
        name: "ip: IPv6 full form",
        args: { type: "ip", value: "2001:0db8:0000:0000:0000:0000:0000:0001" },
        want: "20010db8000000000000000000000001",
      },
      {
        name: "ip: IPv6 embedded IPv4",
        args: { type: "ip", value: "::ffff:192.168.0.1" },
        want: "00000000000000000000ffffc0a80001",
      },
      {
        name: "url: scheme and host case",
        args: { type: "url", value: "HTTPS://Example.COM/path" },
        want: "https://example.com/path",
      },
      {
        name: "url: default port",
        args: { type: "url", value: "https://example.com:443/" },
        want: "https://example.com/",
      },
      {
        name: "url: host trailing dot",
        args: { type: "url", value: "https://example.com./" },
        want: "https://example.com/",
      },
      {
        name: "url: IDN host",
        args: { type: "url", value: "https://bücher.de/" },
        want: "https://xn--bcher-kva.de/",
      },
      {
        name: "guid: case-insensitive",
        args: { type: "guid", value: "33636766-DEE4-4AC5-A4AE-AF8380C7A655" },
        want: "33636766-dee4-4ac5-a4ae-af8380c7a655",
      },
    ];
    for (const t of tests) {
      it(t.name, () => {
        const name = new x509.GeneralName(t.args.type, t.args.value);
        expect(name.canonicalValue).toBe(t.want);
      });
    }
  });

  describe("matches", () => {
    const tests: {
      name: string;
      left: { type: x509.GeneralNameType; value: string };
      right: { type: x509.GeneralNameType; value: string };
      want: boolean;
    }[] = [
      {
        name: "dns: same name",
        left: { type: "dns", value: "example.com" },
        right: { type: "dns", value: "example.com" },
        want: true,
      },
      {
        name: "dns: case difference",
        left: { type: "dns", value: "Example.COM" },
        right: { type: "dns", value: "example.com" },
        want: true,
      },
      {
        name: "dns: trailing dot",
        left: { type: "dns", value: "example.com." },
        right: { type: "dns", value: "example.com" },
        want: true,
      },
      {
        name: "dns: IDN and punycode",
        left: { type: "dns", value: "bücher.de" },
        right: { type: "dns", value: "xn--bcher-kva.de" },
        want: true,
      },
      {
        name: "dns: different names",
        left: { type: "dns", value: "example.com" },
        right: { type: "dns", value: "example.org" },
        want: false,
      },
      {
        name: "dns: suffix is not a match",
        left: { type: "dns", value: "example.com" },
        right: { type: "dns", value: "notexample.com" },
        want: false,
      },
      {
        name: "email: case difference",
        left: { type: "email", value: "User@Example.COM" },
        right: { type: "email", value: "user@example.com" },
        want: true,
      },
      {
        name: "email: different local part",
        left: { type: "email", value: "user@example.com" },
        right: { type: "email", value: "other@example.com" },
        want: false,
      },
      {
        name: "ip: same IPv4",
        left: { type: "ip", value: "192.168.0.1" },
        right: { type: "ip", value: "192.168.0.1" },
        want: true,
      },
      {
        name: "ip: different IPv4",
        left: { type: "ip", value: "192.168.0.1" },
        right: { type: "ip", value: "192.168.0.2" },
        want: false,
      },
      {
        name: "ip: IPv6 compressed and full form",
        left: { type: "ip", value: "::1" },
        right: { type: "ip", value: "0:0:0:0:0:0:0:1" },
        want: true,
      },
      {
        name: "ip: IPv6 embedded IPv4 forms",
        left: { type: "ip", value: "::ffff:192.168.0.1" },
        right: { type: "ip", value: "::ffff:c0a8:1" },
        want: true,
      },
      {
        name: "ip: different IPv6",
        left: { type: "ip", value: "::1" },
        right: { type: "ip", value: "::2" },
        want: false,
      },
      {
        name: "url: case and default port",
        left: { type: "url", value: "HTTPS://Example.COM:443/path" },
        right: { type: "url", value: "https://example.com/path" },
        want: true,
      },
      {
        name: "url: different hosts",
        left: { type: "url", value: "https://example.com/" },
        right: { type: "url", value: "https://example.org/" },
        want: false,
      },
      {
        name: "url: different paths",
        left: { type: "url", value: "https://example.com/a" },
        right: { type: "url", value: "https://example.com/b" },
        want: false,
      },
      {
        name: "upn: same value",
        left: { type: "upn", value: "user@domain.com" },
        right: { type: "upn", value: "user@domain.com" },
        want: true,
      },
      {
        name: "different types: dns vs upn",
        left: { type: "dns", value: "domain.com" },
        right: { type: "upn", value: "domain.com" },
        want: false,
      },
      {
        name: "different types: email vs upn",
        left: { type: "email", value: "user@domain.com" },
        right: { type: "upn", value: "user@domain.com" },
        want: false,
      },
      {
        name: "different types: dns vs url host",
        left: { type: "dns", value: "example.com" },
        right: { type: "url", value: "https://example.com/" },
        want: false,
      },
      {
        name: "different types: ip vs dns",
        left: { type: "ip", value: "192.168.0.1" },
        right: { type: "dns", value: "192.168.0.1" },
        want: false,
      },
    ];
    for (const t of tests) {
      it(t.name, () => {
        const left = new x509.GeneralName(t.left.type, t.left.value);
        const right = new x509.GeneralName(t.right.type, t.right.value);
        expect(left.matches(right)).toBe(t.want);
        expect(right.matches(left)).toBe(t.want);
      });
    }
  });
});

describe("GeneralNames", () => {
  describe("constructor", () => {
    const raw = Buffer.from("302ba41f301d310d300b060355040313046e616d65310c300a060355040a13036f72678208736f6d652e636f6d", "hex");

    const tests: {
      name: string;
      args: x509.JsonGeneralNames | asn1X509.GeneralNames | asn1X509.GeneralName[] | BufferSource;
      want?: x509.JsonGeneralNames;
    }[] = [
      {
        name: "JSON",
        args: [
          {
            type: "dn",
            value: "CN=name, O=org",
          },
          {
            type: "dns",
            value: "some.com",
          },
        ],
        want: [
          {
            type: "dn",
            value: "CN=name, O=org",
          },
          {
            type: "dns",
            value: "some.com",
          },
        ],
      },
      {
        name: "asn:GeneralNames",
        args: asn1Schema.AsnConvert.parse(raw, asn1X509.GeneralNames),
        want: [
          {
            type: "dn",
            value: "CN=name, O=org",
          },
          {
            type: "dns",
            value: "some.com",
          },
        ],
      },
      {
        name: "asn:GeneralName[]",
        args: asn1Schema.AsnConvert.parse(raw, asn1X509.GeneralNames).map((o) => o),
        want: [
          {
            type: "dn",
            value: "CN=name, O=org",
          },
          {
            type: "dns",
            value: "some.com",
          },
        ],
      },
      {
        name: "BufferSource",
        args: raw,
        want: [
          {
            type: "dn",
            value: "CN=name, O=org",
          },
          {
            type: "dns",
            value: "some.com",
          },
        ],
      },
    ];

    for (const t of tests) {
      it(t.name, () => {
        const obj = new x509.GeneralNames(t.args as any);
        expect(obj.toJSON()).toEqual(t.want);
      });
    }
  });

  describe("toString", () => {
    const tests: {
      name: string;
      args: x509.JsonGeneralNames;
      want: string;
    }[] = [
      {
        name: "list of names",
        args: [
          {
            type: "dn",
            value: "CN=name,O=org",
          },
          {
            type: "email",
            value: "some@email.com",
          },
          {
            type: "dns",
            value: "some.com",
          },
          {
            type: "email",
            value: "some2@email.com",
          },
        ],
        want: "GeneralNames:\n  DN: CN=name, O=org\n  Email: some@email.com\n  Email: some2@email.com\n  DNS: some.com",
      },
    ];
    for (const t of tests) {
      it(t.name, () => {
        const name = new x509.GeneralNames(t.args);
        const text = name.toString("text");
        expect(text).toBe(t.want);
      });
    }
  });

  describe("matches", () => {
    it("matches the same names in a different order", () => {
      const left = new x509.GeneralNames([
        { type: "dns", value: "example.com" },
        { type: "email", value: "user@example.com" },
        { type: "ip", value: "192.168.0.1" },
      ]);
      const right = new x509.GeneralNames([
        { type: "ip", value: "192.168.0.1" },
        { type: "dns", value: "Example.COM." },
        { type: "email", value: "User@example.com" },
      ]);
      expect(left.matches(right)).toBe(true);
      expect(right.matches(left)).toBe(true);
    });

    it("matches multi-value names of the same type", () => {
      const left = new x509.GeneralNames([
        { type: "dns", value: "example.com" },
        { type: "dns", value: "www.example.com" },
      ]);
      const right = new x509.GeneralNames([
        { type: "dns", value: "www.example.com" },
        { type: "dns", value: "example.com" },
      ]);
      expect(left.matches(right)).toBe(true);
    });

    it("does not match lists of different sizes", () => {
      const left = new x509.GeneralNames([
        { type: "dns", value: "example.com" },
        { type: "dns", value: "www.example.com" },
      ]);
      const right = new x509.GeneralNames([{ type: "dns", value: "example.com" }]);
      expect(left.matches(right)).toBe(false);
      expect(right.matches(left)).toBe(false);
    });

    it("does not match when a name differs", () => {
      const left = new x509.GeneralNames([
        { type: "dns", value: "example.com" },
        { type: "email", value: "user@example.com" },
      ]);
      const right = new x509.GeneralNames([
        { type: "dns", value: "example.com" },
        { type: "email", value: "other@example.com" },
      ]);
      expect(left.matches(right)).toBe(false);
    });

    it("does not match names of different types with equal text", () => {
      const left = new x509.GeneralNames([{ type: "email", value: "user@domain.com" }]);
      const right = new x509.GeneralNames([{ type: "upn", value: "user@domain.com" }]);
      expect(left.matches(right)).toBe(false);
    });

    it("matches SAN extension names after a DER round trip", () => {
      const san = new x509.SubjectAlternativeNameExtension([
        { type: "dns", value: "example.com" },
        { type: "dns", value: "www.example.com" },
        { type: "email", value: "user@example.com" },
        { type: "ip", value: "192.168.0.1" },
        { type: "url", value: "https://example.com/" },
      ]);
      const parsed = new x509.SubjectAlternativeNameExtension(san.rawData);
      expect(parsed.names.items.length).toBe(5);
      expect(parsed.names.matches(san.names)).toBe(true);
    });
  });
});
