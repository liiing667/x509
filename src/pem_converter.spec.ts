import { describe, it, expect } from "vitest";
import { base64, toArrayBuffer } from "@peculiar/utils";
import * as src from "./index";

describe("PEM", () => {
  const base64_splitted =
    "LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M\n8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk\nJ6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot\ndXd/H5LMDWnonNvPCwQUHg==";
  const base64Text = base64_splitted.replace(/\n/g, "");
  const rawData = toArrayBuffer(base64.decode(base64Text));

  describe("decodeWithHeaders", () => {
    interface PemTest {
      type: string;
      headers: src.PemHeader[];
      rawData: string;
    }

    function mapPemStruct(pem: src.PemStruct): PemTest {
      return {
        ...pem,
        rawData: base64.encode(pem.rawData),
      };
    }

    const tests: {
      name: string;
      pem: string;
      want: PemTest[] | Error;
    }[] = [
      {
        name: "simple pem",
        pem: ["-----BEGIN SOME-----", base64_splitted, "-----END SOME-----"].join("\n"),
        want: [
          {
            type: "SOME",
            headers: [],
            rawData: base64Text,
          },
        ],
      },
      {
        name: "simple pem with CRLF",
        pem: ["-----BEGIN SOME-----", base64_splitted.replace(/\n/g, "\r\n"), "-----END SOME-----"].join("\r\n"),
        want: [
          {
            type: "SOME",
            headers: [],
            rawData: base64Text,
          },
        ],
      },
      {
        name: "pem with blank line",
        pem: [
          "-----BEGIN SOME-----",
          "", // blank line
          base64_splitted,
          "-----END SOME-----",
        ].join("\n"),
        want: [
          {
            type: "SOME",
            headers: [],
            rawData: base64Text,
          },
        ],
      },
      {
        name: "pem with headers",
        pem: [
          "-----BEGIN PRIVACY-ENHANCED MESSAGE-----",
          "Proc-Type: 4,ENCRYPTED",
          "Content-Domain: RFC822",
          "DEK-Info: DES-CBC,F8143EDE5960C597",
          "Originator-ID-Symmetric: linn@zendia.enet.dec.com,,",
          "Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3",
          "Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,",
          "          B70665BB9BF7CBCDA60195DB94F727D3",
          "Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4", // repeated headers
          "Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,",
          "          E2EF532C65CBCFF79F83A2658132DB47",
          "",
          base64_splitted,
          "-----END PRIVACY-ENHANCED MESSAGE-----",
        ].join("\n"),
        want: [
          {
            type: "PRIVACY-ENHANCED MESSAGE",
            headers: [
              {
                key: "Proc-Type",
                value: "4,ENCRYPTED",
              },
              {
                key: "Content-Domain",
                value: "RFC822",
              },
              {
                key: "DEK-Info",
                value: "DES-CBC,F8143EDE5960C597",
              },
              {
                key: "Originator-ID-Symmetric",
                value: "linn@zendia.enet.dec.com,,",
              },
              {
                key: "Recipient-ID-Symmetric",
                value: "linn@zendia.enet.dec.com,ptf-kmc,3",
              },
              {
                key: "Key-Info",
                value: "DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,B70665BB9BF7CBCDA60195DB94F727D3",
              },
              {
                key: "Recipient-ID-Symmetric",
                value: "pem-dev@tis.com,ptf-kmc,4",
              },
              {
                key: "Key-Info",
                value: "DES-ECB,RSA-MD2,161A3F75DC82EF26,E2EF532C65CBCFF79F83A2658132DB47",
              },
            ],
            rawData: base64Text,
          },
        ],
      },
      {
        name: "multiple PEM blocks",
        pem: [
          "odd text",
          "-----BEGIN SOME1-----",
          base64_splitted,
          "-----END SOME1-----",
          "",
          "-----BEGIN SOME2-----",
          "Key1: Value1",
          "",
          base64_splitted,
          "-----END SOME2-----",
          "odd text",
          "-----BEGIN SOME1-----",
          "",
          base64_splitted,
          "-----END SOME2-----", // incorrect type
        ].join("\n"),
        want: [
          {
            type: "SOME1",
            headers: [],
            rawData: base64Text,
          },
          {
            type: "SOME2",
            headers: [
              {
                key: "Key1",
                value: "Value1",
              },
            ],
            rawData: base64Text,
          },
        ],
      },
      {
        name: "BEGIN and END types are not equal",
        pem: ["-----BEGIN SOME1-----", base64_splitted, "-----END SOME2-----"].join("\n"),
        want: [],
      },
      {
        name: "odd text before BEGIN",
        pem: ["Some: value", "-----BEGIN SOME-----", base64_splitted, "-----END SOME-----"].join("\n"),
        want: [
          {
            type: "SOME",
            headers: [],
            rawData: base64Text,
          },
        ],
      },
    ];
    tests.forEach((t) => {
      it(t.name, () => {
        if (t.want instanceof Error) {
          expect(() => {
            src.PemConverter.decodeWithHeaders(t.pem);
          }).toThrow(t.want);
        } else {
          const res = src.PemConverter.decodeWithHeaders(t.pem);

          expect(res.map(mapPemStruct)).toEqual(t.want);
        }
      });
    });
  });

  describe("encode", () => {
    const tests: {
      name: string;
      args: { a: BufferSource | BufferSource[] | src.PemStructEncodeParams[]; b?: string };
      want: string | Error;
    }[] = [
      {
        name: "PEM without headers from PemStruct",
        args: {
          a: [
            {
              type: "SOME",
              rawData,
            },
          ],
        },
        want: ["-----BEGIN SOME-----", base64_splitted, "-----END SOME-----"].join("\n"),
      },
      {
        name: "PEM with headers from PemStruct",
        args: {
          a: [
            {
              type: "SOME",
              headers: [
                {
                  key: "Key1",
                  value: "Value1",
                },
                {
                  key: "Key2",
                  value: "Value2",
                },
                {
                  key: "Key1",
                  value: "Value3",
                }, // repeated key
              ],
              rawData,
            },
          ],
        },
        want: ["-----BEGIN SOME-----", "Key1: Value1", "Key2: Value2", "Key1: Value3", "", base64_splitted, "-----END SOME-----"].join("\n"),
      },
      {
        name: "multiple PEM blocks",
        args: {
          a: [
            {
              type: "SOME1",
              rawData,
            },
            {
              type: "SOME2",
              headers: [
                {
                  key: "Key1",
                  value: "Value1",
                },
              ],
              rawData,
            },
          ],
        },
        want: ["-----BEGIN SOME1-----", base64_splitted, "-----END SOME1-----", "-----BEGIN SOME2-----", "Key1: Value1", "", base64_splitted, "-----END SOME2-----"].join("\n"),
      },
      {
        name: "PEM from BufferSource",
        args: {
          a: rawData,
          b: "SOME",
        },
        want: ["-----BEGIN SOME-----", base64_splitted, "-----END SOME-----"].join("\n"),
      },
      {
        name: "PEM from BufferSource[]",
        args: {
          a: [rawData, rawData],
          b: "SOME",
        },
        want: ["-----BEGIN SOME-----", base64_splitted, "-----END SOME-----", "-----BEGIN SOME-----", base64_splitted, "-----END SOME-----"].join("\n"),
      },
    ];

    tests.forEach((t) => {
      it(t.name, () => {
        if (t.want instanceof Error) {
          expect(() => {
            src.PemConverter.encode.call<unknown, any[], unknown>(src.PemConverter, t.args.a, t.args.b);
          }).toThrow(t.want);
        } else {
          const pem = src.PemConverter.encode.call<unknown, any[], unknown>(src.PemConverter, t.args.a, t.args.b);
          expect(pem).toBe(t.want);
        }
      });
    });
  });

  describe("isPem", () => {
    const tests: {
      name: string;
      data: any;
      want: boolean;
    }[] = [
      {
        name: "valid PEM with Unix line endings",
        data: ["-----BEGIN SOME-----", base64_splitted, "-----END SOME-----"].join("\n"),
        want: true,
      },
      {
        name: "valid PEM with DOS line endings",
        data: ["-----BEGIN SOME-----", base64_splitted.replace(/\n/g, "\r\n"), "-----END SOME-----"].join("\r\n"),
        want: true,
      },
      {
        name: "invalid PEM - not a string",
        data: 123,
        want: false,
      },
      {
        name: "invalid PEM - wrong format",
        data: "This is not a PEM",
        want: false,
      },
      {
        name: "empty string",
        data: "",
        want: false,
      },
    ];

    tests.forEach((t) => {
      it(t.name, () => {
        const result = src.PemConverter.isPem(t.data);
        expect(result).toBe(t.want);
      });
    });
  });

  describe("inspect", () => {
    const certBlock = ["-----BEGIN CERTIFICATE-----", base64_splitted, "-----END CERTIFICATE-----"].join("\n");
    const crlBlock = ["-----BEGIN CRL-----", base64_splitted, "-----END CRL-----"].join("\n");
    const csrBlock = ["-----BEGIN CERTIFICATE REQUEST-----", base64_splitted, "-----END CERTIFICATE REQUEST-----"].join("\n");

    it("single certificate block", () => {
      const inventory = src.PemConverter.inspect(certBlock);

      expect(inventory.ok).toBe(true);
      expect(inventory.blocks.length).toBe(1);
      expect(inventory.blocks[0].type).toBe("CERTIFICATE");
      expect(inventory.blocks[0].index).toBe(0);
      expect(inventory.blocks[0].offset).toBe(0);
      expect(inventory.dangling).toEqual([]);
      expect(inventory.issues).toEqual([]);
    });

    it("single CRL and CSR blocks", () => {
      for (const pem of [crlBlock, csrBlock]) {
        const inventory = src.PemConverter.inspect(pem);

        expect(inventory.ok).toBe(true);
        expect(inventory.blocks.length).toBe(1);
        expect(inventory.issues).toEqual([]);
      }
    });

    it("empty and whitespace only input", () => {
      for (const pem of ["", "  \n \n"]) {
        const inventory = src.PemConverter.inspect(pem);

        expect(inventory.ok).toBe(true);
        expect(inventory.blocks).toEqual([]);
        expect(inventory.dangling).toEqual([]);
        expect(inventory.issues).toEqual([]);
      }
    });

    it("mixed bundle with duplicates, unknown type, truncated block and trailing text", () => {
      const pem = [
        "leading text",
        certBlock,
        certBlock, // duplicate
        "-----BEGIN FOO-----",
        base64_splitted,
        "-----END FOO-----",
        "trailing text",
        "-----BEGIN BAR-----",
        base64_splitted,
      ].join("\n");

      const inventory = src.PemConverter.inspect(pem);

      expect(inventory.ok).toBe(false);
      expect(inventory.blocks.length).toBe(3);
      expect(inventory.blocks.map((o) => o.type)).toEqual(["CERTIFICATE", "CERTIFICATE", "FOO"]);

      // blocks match what the loader sees
      const structs = src.PemConverter.decodeWithHeaders(pem);
      expect(inventory.blocks.map((o) => ({ type: o.type, headers: o.headers, rawData: o.rawData }))).toEqual(structs.map((o) => ({ type: o.type, headers: o.headers, rawData: o.rawData })));

      expect(inventory.dangling.map((o) => o.kind)).toEqual(["text", "text", "truncated"]);
      expect(inventory.dangling[0].text).toBe("leading text");
      expect(inventory.dangling[1].text).toBe("trailing text");
      expect(inventory.dangling[2].type).toBe("BAR");

      const issueTypes = inventory.issues.map((o) => o.type);
      expect(issueTypes).toContain("duplicate");
      expect(issueTypes).toContain("unknown-type");
      expect(issueTypes.filter((o) => o === "dangling").length).toBe(3);

      const duplicate = inventory.issues.find((o) => o.type === "duplicate");
      expect(duplicate?.blocks).toEqual([0, 1]);

      const unknown = inventory.issues.find((o) => o.type === "unknown-type");
      expect(unknown?.blocks).toEqual([2]);
    });

    it("mismatched END type", () => {
      const pem = ["-----BEGIN CERTIFICATE-----", base64_splitted, "-----END CRL-----"].join("\n");

      const inventory = src.PemConverter.inspect(pem);

      expect(inventory.ok).toBe(false);
      expect(inventory.blocks).toEqual([]);
      expect(inventory.dangling.length).toBe(1);
      expect(inventory.dangling[0].kind).toBe("mismatched-end");
      expect(inventory.dangling[0].type).toBe("CERTIFICATE");
      expect(inventory.dangling[0].endType).toBe("CRL");
      expect(inventory.issues.map((o) => o.type)).toEqual(["dangling"]);
    });

    it("malformed block body", () => {
      const pem = ["-----BEGIN CERTIFICATE-----", "not a base64 body !!!", "-----END CERTIFICATE-----"].join("\n");

      const inventory = src.PemConverter.inspect(pem);

      expect(inventory.ok).toBe(false);
      expect(inventory.blocks).toEqual([]);
      expect(inventory.dangling.length).toBe(1);
      expect(inventory.dangling[0].kind).toBe("malformed");
      expect(inventory.dangling[0].type).toBe("CERTIFICATE");
    });

    it("dangling content between valid blocks", () => {
      const pem = [certBlock, "odd text", crlBlock].join("\n");

      const inventory = src.PemConverter.inspect(pem);

      expect(inventory.ok).toBe(false);
      expect(inventory.blocks.map((o) => o.type)).toEqual(["CERTIFICATE", "CRL"]);
      expect(inventory.dangling.length).toBe(1);
      expect(inventory.dangling[0].kind).toBe("text");
      expect(inventory.dangling[0].text).toBe("odd text");
      expect(inventory.dangling[0].offset).toBe(certBlock.length + 1);
    });

    it("custom knownTypes option", () => {
      const inventory = src.PemConverter.inspect(certBlock, { knownTypes: ["FOO"] });

      expect(inventory.ok).toBe(false);
      expect(inventory.issues.length).toBe(1);
      expect(inventory.issues[0].type).toBe("unknown-type");
      expect(inventory.issues[0].blocks).toEqual([0]);
    });

    it("CRLF line endings", () => {
      const pem = [certBlock, "trailing text"].join("\n").replace(/\n/g, "\r\n");

      const inventory = src.PemConverter.inspect(pem);

      expect(inventory.blocks.length).toBe(1);
      expect(inventory.dangling.length).toBe(1);
      expect(inventory.dangling[0].kind).toBe("text");
    });
  });
});
