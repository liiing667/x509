import { AsnConvert } from "@peculiar/asn1-schema";
import * as asnX509 from "@peculiar/asn1-x509";
import { describe, expect, it } from "vitest";
import * as x509 from "../index";
import { TextConverter } from "../text_converter";

describe("CertificatePolicyExtension", () => {
  describe("constructors", () => {
    it("parses plain policy identifiers and keeps the legacy list", () => {
      const ext = new x509.CertificatePolicyExtension(["1.2.3.4.5", "1.2.3.4.5.6"], false);
      const parsed = new x509.CertificatePolicyExtension(ext.rawData);

      expect(parsed.policies).toEqual(["1.2.3.4.5", "1.2.3.4.5.6"]);
      expect(parsed.items.map((policy) => policy.policyIdentifier)).toEqual(["1.2.3.4.5", "1.2.3.4.5.6"]);
      expect(parsed.items.every((policy) => policy.qualifiers.length === 0)).toBe(true);
      expect(parsed.critical).toBe(false);
    });

    it("preserves a critical flag", () => {
      const ext = new x509.CertificatePolicyExtension(["1.2.3.4.5"], true);

      expect(ext.critical).toBe(true);
      expect(new x509.CertificatePolicyExtension(ext.rawData).critical).toBe(true);
    });
  });

  describe("items", () => {
    it("keeps duplicate policy identifiers one item per PolicyInformation", () => {
      const value = new asnX509.CertificatePolicies([new asnX509.PolicyInformation({ policyIdentifier: "1.2.3.4.5" }), new asnX509.PolicyInformation({ policyIdentifier: "1.2.3.4.5" })]);
      const ext = new x509.CertificatePolicyExtension(new x509.Extension(asnX509.id_ce_certificatePolicies, false, AsnConvert.serialize(value)).rawData);

      expect(ext.policies).toEqual(["1.2.3.4.5", "1.2.3.4.5"]);
      expect(ext.items).toHaveLength(2);
      expect(ext.items[0].policyIdentifier).toBe(ext.items[1].policyIdentifier);
      expect(ext.asnPolicies).toHaveLength(2);
    });

    it("parses cps and userNotice qualifiers", () => {
      const value = new asnX509.CertificatePolicies([
        new asnX509.PolicyInformation({
          policyIdentifier: "1.2.3.4.5",
          policyQualifiers: [
            new asnX509.PolicyQualifierInfo({
              policyQualifierId: asnX509.id_qt_csp,
              qualifier: AsnConvert.serialize(new asnX509.Qualifier({ cPSuri: "https://example.com/cps" })),
            }),
            new asnX509.PolicyQualifierInfo({
              policyQualifierId: asnX509.id_qt_unotice,
              qualifier: AsnConvert.serialize(
                new asnX509.Qualifier({
                  userNotice: new asnX509.UserNotice({
                    explicitText: new asnX509.DisplayText({ utf8String: "example notice" }),
                  }),
                }),
              ),
            }),
          ],
        }),
      ]);
      const ext = new x509.CertificatePolicyExtension(wrapExtension(value).rawData);

      expect(ext.policies).toEqual(["1.2.3.4.5"]);
      expect(ext.items[0].qualifiers).toHaveLength(2);

      const cps = ext.items[0].qualifiers[0];
      expect(cps.type).toBe("cpsUri");
      if (cps.type === "cpsUri") {
        expect(cps.value).toBe("https://example.com/cps");
      }

      const notice = ext.items[0].qualifiers[1];
      expect(notice.type).toBe("userNotice");
      if (notice.type === "userNotice") {
        expect(notice.value.explicitText?.utf8String).toBe("example notice");
      }
    });

    it("preserves unknown qualifiers with their original bytes", () => {
      const unknownQualifier = new Uint8Array([0x0c, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
      const value = new asnX509.CertificatePolicies([
        new asnX509.PolicyInformation({
          policyIdentifier: "1.2.3.4.5",
          policyQualifiers: [
            new asnX509.PolicyQualifierInfo({
              policyQualifierId: "1.2.3.4.9.9",
              qualifier: unknownQualifier.buffer as ArrayBuffer,
            }),
          ],
        }),
      ]);
      const ext = new x509.CertificatePolicyExtension(wrapExtension(value).rawData);

      expect(ext.items[0].qualifiers).toHaveLength(1);
      const qualifier = ext.items[0].qualifiers[0];
      expect(qualifier.type).toBe("unknown");
      if (qualifier.type === "unknown") {
        expect(qualifier.oid).toBe("1.2.3.4.9.9");
        expect(Buffer.from(qualifier.value)).toEqual(Buffer.from(unknownQualifier));
      }
      expect(ext.policies).toEqual(["1.2.3.4.5"]);
    });

    it("falls back to raw bytes when a known qualifier id carries malformed data", () => {
      const malformed = new Uint8Array([0x02, 0x01, 0x01]);
      const value = new asnX509.CertificatePolicies([
        new asnX509.PolicyInformation({
          policyIdentifier: "1.2.3.4.5",
          policyQualifiers: [
            new asnX509.PolicyQualifierInfo({
              policyQualifierId: asnX509.id_qt_csp,
              qualifier: malformed.buffer as ArrayBuffer,
            }),
          ],
        }),
      ]);
      const ext = new x509.CertificatePolicyExtension(wrapExtension(value).rawData);

      const qualifier = ext.items[0].qualifiers[0];
      expect(qualifier.type).toBe("unknown");
      if (qualifier.type === "unknown") {
        expect(qualifier.oid).toBe(asnX509.id_qt_csp);
        expect(Buffer.from(qualifier.value)).toEqual(Buffer.from(malformed));
      }
    });

    it("returns one parsed result per extension when duplicates exist", () => {
      const first = new x509.CertificatePolicyExtension(["1.2.3.4.5"], false);
      const second = new x509.CertificatePolicyExtension(["1.2.3.4.5", "1.2.3.4.6"], true);

      expect(first.critical).toBe(false);
      expect(second.critical).toBe(true);
      expect(first.items).toHaveLength(1);
      expect(second.items).toHaveLength(2);
      expect(first.policies).toEqual(["1.2.3.4.5"]);
      expect(second.policies).toEqual(["1.2.3.4.5", "1.2.3.4.6"]);
    });
  });

  describe("toTextObject", () => {
    it("keeps the legacy text output", () => {
      const ext = new x509.CertificatePolicyExtension(["1.2.3.4.5", "1.2.3.4.5.6"], false);

      expect(TextConverter.serialize(ext.toTextObject())).toBe(["Certificate Policies:", "  Policy: 1.2.3.4.5", "  Policy: 1.2.3.4.5.6"].join("\n"));
    });
  });
});

function wrapExtension(value: asnX509.CertificatePolicies): x509.Extension {
  return new x509.Extension(asnX509.id_ce_certificatePolicies, false, AsnConvert.serialize(value));
}
