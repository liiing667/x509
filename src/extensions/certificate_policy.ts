import * as asnX509 from "@peculiar/asn1-x509";
import { AsnConvert } from "@peculiar/asn1-schema";
import { isBufferSource } from "@peculiar/utils";
import { Extension } from "../extension";
import { OidSerializer, TextObject } from "../text_converter";
import type { ParseOptions } from "../types";
import { ExtensionFactory } from "./extension_factory";

/**
 * A CPS URI policy qualifier (`id-qt-cps`)
 */
export interface CertificatePolicyCpsUriQualifier {
  /**
   * Policy qualifier identifier (`1.3.6.1.5.5.7.2.1`)
   */
  type: "cpsUri";
  /**
   * Certification Practice Statement URI
   */
  value: string;
}

/**
 * A user notice policy qualifier (`id-qt-unotice`)
 */
export interface CertificatePolicyUserNoticeQualifier {
  /**
   * Policy qualifier identifier (`1.3.6.1.5.5.7.2.2`)
   */
  type: "userNotice";
  /**
   * Parsed user notice
   */
  value: asnX509.UserNotice;
}

/**
 * A policy qualifier that has no well-known identifier or whose value
 * cannot be parsed. The original DER encoded qualifier is preserved.
 */
export interface CertificatePolicyUnknownQualifier {
  /**
   * Policy qualifier identifier
   */
  type: "unknown";
  /**
   * Original policy qualifier identifier OID
   */
  oid: string;
  /**
   * DER encoded value of the qualifier
   */
  value: ArrayBuffer;
}

/**
 * Represents a policy qualifier
 */
export type CertificatePolicyQualifier = CertificatePolicyCpsUriQualifier | CertificatePolicyUserNoticeQualifier | CertificatePolicyUnknownQualifier;

/**
 * Represents a single certificate policy together with its qualifiers
 */
export interface CertificatePolicy {
  /**
   * Certificate policy identifier OID
   */
  policyIdentifier: string;
  /**
   * Policy qualifiers in their original order
   */
  qualifiers: CertificatePolicyQualifier[];
}

/**
 * Represents the Certificate Policy extension
 */
export class CertificatePolicyExtension extends Extension {
  public static override NAME = "Certificate Policies";

  /**
   * Gets the list of certificate policy identifier OIDs in their original order
   */
  public readonly policies: readonly string[];

  /**
   * Gets the parsed certificate policies, one entry per `PolicyInformation`
   * in the extension. Duplicate policy identifiers are kept and every
   * qualifier, including unknown ones, is preserved.
   */
  public readonly items: readonly CertificatePolicy[];

  /**
   * Gets the original parsed ASN.1 policy information
   */
  public readonly asnPolicies: readonly asnX509.PolicyInformation[];

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   * @param options Optional ASN.1 parse options (e.g. `asn1js.fromBER` resource limits)
   */
  constructor(raw: BufferSource, options?: ParseOptions);
  /**
   * Creates a new instance
   * @param policies
   * @param critical
   */
  constructor(policies: string[], critical?: boolean);
  constructor(...args: any[]) {
    let asnPolicies: asnX509.CertificatePolicies;

    if (isBufferSource(args[0])) {
      super(args[0] as BufferSource, args[1] as ParseOptions | undefined);

      asnPolicies = AsnConvert.parse(this.value, asnX509.CertificatePolicies, this.parseOptions);
    } else {
      const policies = args[0] as string[];
      const critical = args[1] ?? false;

      asnPolicies = new asnX509.CertificatePolicies(policies.map((o) => new asnX509.PolicyInformation({ policyIdentifier: o })));

      super(asnX509.id_ce_certificatePolicies, critical, AsnConvert.serialize(asnPolicies));
    }

    this.asnPolicies = asnPolicies;
    this.items = asnPolicies.map((policy) => parseCertificatePolicy(policy, this.parseOptions));
    this.policies = this.items.map((policy) => policy.policyIdentifier);
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj["Policy"] = this.policies.map((o) => new TextObject("", {}, OidSerializer.toString(o)));

    return obj;
  }
}

ExtensionFactory.register(asnX509.id_ce_certificatePolicies, CertificatePolicyExtension);

function parseCertificatePolicy(policy: asnX509.PolicyInformation, options?: ParseOptions): CertificatePolicy {
  const qualifiers: CertificatePolicyQualifier[] = [];

  for (const qualifierInfo of policy.policyQualifiers ?? []) {
    qualifiers.push(parsePolicyQualifier(qualifierInfo, options));
  }

  return {
    policyIdentifier: policy.policyIdentifier,
    qualifiers,
  };
}

function parsePolicyQualifier(qualifierInfo: asnX509.PolicyQualifierInfo, options?: ParseOptions): CertificatePolicyQualifier {
  try {
    switch (qualifierInfo.policyQualifierId) {
      case asnX509.id_qt_csp: {
        const qualifier = AsnConvert.parse(qualifierInfo.qualifier, asnX509.Qualifier, options);
        if (qualifier.cPSuri !== undefined) {
          return {
            type: "cpsUri",
            value: qualifier.cPSuri,
          };
        }
        break;
      }
      case asnX509.id_qt_unotice: {
        const qualifier = AsnConvert.parse(qualifierInfo.qualifier, asnX509.Qualifier, options);
        if (qualifier.userNotice) {
          return {
            type: "userNotice",
            value: qualifier.userNotice,
          };
        }
        break;
      }
    }
  } catch {
    // Malformed qualifier value: keep the original bytes instead of failing
    // the whole extension parse.
  }

  return {
    type: "unknown",
    oid: qualifierInfo.policyQualifierId,
    value: qualifierInfo.qualifier,
  };
}
