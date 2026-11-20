import { describe, it, expect } from "vitest";
import { base64, toArrayBuffer } from "@peculiar/utils";
import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificationRequest } from "@peculiar/asn1-csr";
import { Name as AsnName, SubjectPublicKeyInfo } from "@peculiar/asn1-x509";
import * as asn1js from "asn1js";
import * as x509 from "./index";

describe("crypto", () => {
  describe("Pkcs10CertificateRequest", () => {
    const crypto = x509.cryptoProvider.get();

    const rsaAlgorithm = {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    };
    const signingAlgorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    const generateKeys = () => crypto.subtle.generateKey(rsaAlgorithm, false, ["sign", "verify"]);

    it("read", () => {
      const pem =
        "MIICdDCCAVwCAQAwLzEtMA8GA1UEAxMIdGVzdE5hbWUwGgYJKoZIhvcNAQkBEw10ZXN0QG1haWwubm90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";
      const csr = new x509.Pkcs10CertificateRequest(toArrayBuffer(base64.decode(pem)));
      expect(csr.subject).toBe("CN=testName+E=test@mail.not");
    });

    it("verify", async () => {
      const pem =
        "MIICRzCCAS8CAQAwAjEAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";
      const csr = new x509.Pkcs10CertificateRequest(toArrayBuffer(base64.decode(pem)));
      const ok = await csr.verify();
      expect(ok).toBe(true);
    });

    describe("request identity", () => {
      it("keeps a normal CSR with attributes and extensions verifiable", async () => {
        const keys = await generateKeys();
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Test",
          keys,
          signingAlgorithm,
          extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature)],
          attributes: [new x509.ChallengePasswordAttribute("password")],
        });

        const parsed = new x509.Pkcs10CertificateRequest(csr.rawData);
        expect(await parsed.verify()).toBe(true);
        expect(parsed.subject).toBe("CN=Test");
        expect(parsed.attributes.length).toBe(2);
        expect(parsed.extensions.length).toBe(1);
      });

      it("exposes no attributes for an empty attribute set", async () => {
        const keys = await generateKeys();
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Empty",
          keys,
          signingAlgorithm,
        });
        expect(csr.attributes).toEqual([]);
        expect(await csr.verify()).toBe(true);
      });

      it("accepts a CSR whose empty attributes element is omitted", async () => {
        const keys = await generateKeys();
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Empty",
          keys,
          signingAlgorithm,
        });
        const asn = AsnConvert.parse(csr.rawData, CertificationRequest);
        const info = asn.certificationRequestInfo;

        // Rebuild the request without the [0] attributes element at all and
        // re-sign, the form OpenSSL accepts as an empty attribute set.
        const infoNoAttributes = new asn1js.Sequence({
          value: [new asn1js.Integer({ value: info.version }), asn1js.fromBER(AsnConvert.serialize(info.subject)).result, asn1js.fromBER(AsnConvert.serialize(info.subjectPKInfo)).result],
        });
        const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keys.privateKey, infoNoAttributes.toBER(false));
        const raw = new asn1js.Sequence({
          value: [infoNoAttributes, asn1js.fromBER(AsnConvert.serialize(asn.signatureAlgorithm)).result, new asn1js.BitString({ valueHex: signature })],
        }).toBER(false);

        const omitted = new x509.Pkcs10CertificateRequest(raw);
        expect(omitted.attributes).toEqual([]);
        expect(omitted.subject).toBe("CN=Empty");
        expect(await omitted.verify()).toBe(true);
      });

      it("rejects duplicate attributes", async () => {
        const keys = await generateKeys();
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Test",
          keys,
          signingAlgorithm,
          extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature)],
        });

        const asn = AsnConvert.parse(csr.rawData, CertificationRequest);
        const extensionRequest = asn.certificationRequestInfo.attributes[0]!;
        asn.certificationRequestInfo.attributes.push(extensionRequest);
        const raw = AsnConvert.serialize(asn);

        expect(() => new x509.Pkcs10CertificateRequest(raw)).toThrow(/duplicate/i);
      });

      it("rejects a forged subject public key info", async () => {
        const victimKeys = await generateKeys();
        const victimCsr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Victim",
          keys: victimKeys,
          signingAlgorithm,
        });
        const attackerKeys = await generateKeys();

        // Keep the originally signed TBS bytes, but present the attacker's public
        // key through the parsed view, and re-sign those bytes with the attacker's
        // key so the cryptographic check alone cannot spot the swap.
        const asn = AsnConvert.parse(victimCsr.rawData, CertificationRequest);
        const attackerSpki = await crypto.subtle.exportKey("spki", attackerKeys.publicKey);
        asn.certificationRequestInfo.subjectPKInfo = AsnConvert.parse(attackerSpki, SubjectPublicKeyInfo);
        asn.signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, attackerKeys.privateKey, asn.certificationRequestInfoRaw!);

        const forged = new x509.Pkcs10CertificateRequest(asn);
        expect(await forged.verify()).toBe(false);
      });

      it("rejects a forged subject", async () => {
        const keys = await generateKeys();
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Victim",
          keys,
          signingAlgorithm,
        });

        // Keep the signed TBS bytes and signature, but show a different subject
        // through the parsed view.
        const asn = AsnConvert.parse(csr.rawData, CertificationRequest);
        asn.certificationRequestInfo.subject = AsnConvert.parse(new x509.Name("CN=Forged").toArrayBuffer(), AsnName);

        const forged = new x509.Pkcs10CertificateRequest(asn);
        expect(forged.subject).toBe("CN=Forged");
        expect(await forged.verify()).toBe(false);
      });

      it("rejects a wrong signature", async () => {
        const keys = await generateKeys();
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          name: "CN=Test",
          keys,
          signingAlgorithm,
        });

        const der = new Uint8Array(csr.rawData.slice(0));
        der[der.length - 1] = der[der.length - 1]! ^ 0x01;

        const tampered = new x509.Pkcs10CertificateRequest(der.buffer);
        expect(await tampered.verify()).toBe(false);
      });
    });
  });
});
