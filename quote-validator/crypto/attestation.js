import Data from "./data.js"
import { fromBER } from 'asn1js'
import {setEngine, CryptoEngine, CertificateRevocationList, CertificateChainValidationEngine, Certificate } from 'pkijs'

import crypto from 'crypto'

import { Seeker } from "./pack.js";

const INTEL_ROOT_CA = `-----BEGIN CERTIFICATE-----
  MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
  aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
  cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
  BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG
  A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
  aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
  AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
  1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
  uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
  MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
  ZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
  Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYI
  KoZIzj0EAwIDSQAwRgIhAIpQ/KlO1XE4hH8cw5Ol/E0yzs8PToJe9Pclt+bhfLUg
  AiEAss0qf7FlMmAMet+gbpLD97ldYy/wqjjmwN7yHRVr2AM=
  -----END CERTIFICATE-----`;


const ber = INTEL_ROOT_CA.match(/(?:-+BEGIN CERTIFICATE-+)([\s\S]+?)(?:-+END CERTIFICATE-+)/i)
const intelRootCA = new Certificate({
  schema: fromBER(Data.fromBase64(ber[1].replace(/\s/g, "")).createArrayBuffer()).result
})

const getCRLDistrubutionPoints = (certificate) => { 
  const decode = buffer => new TextDecoder().decode(buffer)

  return certificate.extensions
    .filter(extension => extension.parsedValue)
    .filter(extension => extension.parsedValue.distributionPoints)
    .map(e => e.extnValue.valueBeforeDecode)
    .map(val => decode(val))
    .map(brokenUrl => brokenUrl.replace(/^.+http/,'http'))
}

const getPublicKey = certificate => {
  return importPublicECDSAKey(new Data(certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
}

const importPublicECDSAKey = (bitstring) => {
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: bitstring.slice(1, 33).toBase64URL().slice(0, -1),
      y: bitstring.slice(33, 65).toBase64URL().slice(0, -1)
    },
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ['verify']
  )
  
}

setEngine(
  "newEngine",
  crypto,
  new CryptoEngine({ name: "", crypto, subtle: crypto.subtle })
);

const INTEL_ISVPRODID = 1;
const INTEL_ISVSVN = 2;
const INTEL_QUOTE_VERSION = 3;
const OE_SGX_PCK_ID_PCK_CERT_CHAIN = 5;
const HEADER_VERSION = 1;
const REMOTE_REPORT_TYPE = 2;

function parseReportBody(seeker) {
  //  u8[16] cpusvn
  //  u32    miscselect
  //  u8[28] reserved
  //  struct attributes
  //  u8[32] mrenclave
  //  u8[32] reserved
  //  u8[32] mrsigner
  //  u8[96] reserved
  //  u16    isvprodid
  //  u16    isvsvn
  //  u8[60] reserved
  //  u8[64] report_data

  const raw = seeker.extract(16 + 4 + 28 + 8 + 8 + 32 + 32 + 32 + 96 + 2 + 2 + 60 + 64);
  seeker = new Seeker(raw);

  const cpusvn = seeker.extract(16);
  const miscselect = seeker.extractLEU32();
  /* reserved */ seeker.skip(28);
  const attributes = (() => {
    //  u64 flags
    //  u64 xfrm

    const flags = seeker.extractLEU64();
    const xfrm = seeker.extractLEU64();

    return {
      flags,
      xfrm
    }
  })();
  const mrenclave = seeker.extract(32);
  /* reserved */ seeker.skip(32);
  const mrsigner = seeker.extract(32);
  /* reserved */ seeker.skip(96);
  const isvprodid = seeker.extractLEU16();
  const isvsvn = seeker.extractLEU16();
  /* reserved */ seeker.skip(60);
  const reportData = seeker.extract(64);

  return {
    cpusvn,
    miscselect,
    attributes,
    uniqueID: mrenclave,
    signerID: mrsigner,
    productID: new Data(new Uint8Array([
      (isvprodid & 0x00FF), (isvprodid & 0xFF00) >> 8,
      // OpenEnclave product ID is 16 bytes, pad with zeros.
      ...new Array(14).fill(0x00)
    ])),
    securityVersion: isvsvn,
    reportData,
    signedData: raw
  }
}

async function parseSignature(seeker) {
  // u8[32] r
  // u8[32] s

  // see https://tools.ietf.org/html/rfc3278#section-8.2 for more information.

  const r = seeker.extract(32);
  const s = seeker.extract(32);
  const data = Data.join([r, s]);
  return data;
}

async function parsePublicECDSAKey(seeker) {
  // u8[32] x
  // u8[32] y

  const x = seeker.extract(32);
  const y = seeker.extract(32);

  const key = await importPublicECDSAKey(Data.join([[0x04], x, y]))

  return {
    key,
    raw: Data.join([x, y])
  };

}

async function parseReport(report) {
  const seeker = new Seeker(report);

  return await (async () => {
    //  u16                version
    //  u16                sign_type
    //  u8[4]              reserved
    //  u16                qe_svn
    //  u16                pce_svn
    //  u8[16]             uuid
    //  u8[20]             user_data
    //  struct             sgx_report_body
    //  u32                signature_size
    //  u8[signature_size] signature

    const pos1 = seeker.pos;
    const version = seeker.extractLEU16();
    const signType = seeker.extractLEU16();
    /* reserved */ seeker.skip(4);
    const qeSVN = seeker.extractLEU16();
    const pceSVN = seeker.extractLEU16();
    const uuid = seeker.extract(16);
    const userData = seeker.extract(20);
    const reportBody = parseReportBody(seeker);
    const signedData = report.slice(pos1, seeker.pos);
    const signatureSize = seeker.extractLEU32();

    const quoteAuthData = await (async () => {
      //  u8[64] signature
      //  u8[64] attestation_key
      //  struct qe_report_body
      //  u8[64] qe_report_body_signature

      const signature = await parseSignature(seeker);
      const attestationKey = await parsePublicECDSAKey(seeker);
      const qeReportBody = parseReportBody(seeker);
      const qeReportBodySignature = await parseSignature(seeker);

      return {
        signature,
        attestationKey,
        qeReportBody,
        qeReportBodySignature
      }
    })();

    const qeAuthData = (() => {
      // u16      size
      // u8[size] data

      const size = seeker.extractLEU16();
      const data = seeker.extract(size);

      return data;
    })();

    const qeCertData = (() => {
      // u16      type
      // u32      size
      // u8[size] data

      const type = seeker.extractLEU16();
      const size = seeker.extractLEU32();
      const data = seeker.extract(size);

      return {
        type,
        data
      };
    })();

    if (seeker.remaining > 0) throw Error(`${seeker.remaining} bytes still remaining in report.`);

    return {
      version,
      signType,
      qeSVN,
      pceSVN,
      uuid,
      userData,
      reportBody,
      quoteAuthData,
      qeAuthData,
      qeCertData,
      signedData
    };
  })();
}

export const verifyReport = async (report, { securityVersion = 0, MRENCLAVE, signerID, productID }) => {
  // Parse report
  const quote = await parseReport(report);

  // Sanity check
  if (quote.version != INTEL_QUOTE_VERSION) throw Error(`Unexpected quote version ${quote.version}. Expected ${INTEL_QUOTE_VERSION}.`);
  if (quote.qeCertData.type != OE_SGX_PCK_ID_PCK_CERT_CHAIN) throw Error(`Missing certificate chain.`);
  if (!quote.qeCertData.data) throw Error(`Missing certificate.`);

  // Parse certificate chain
  const certificateChain = quote.qeCertData.data.toUTF8().match(/(-+BEGIN CERTIFICATE-+[\s\S]+?-+END CERTIFICATE-+)/g)

  for (let i = 0; i < certificateChain.length; ++i) {
    const pem = certificateChain[i].match(/(?:-+BEGIN CERTIFICATE-+)([\s\S]+?)(?:-+END CERTIFICATE-+)/i)
    const data = Data.fromBase64(pem[1].replace(/\s/g, "")).createArrayBuffer()
    certificateChain[i] = new Certificate({
      schema: fromBER(data).result
    })
  }
  
  const allCrls = certificateChain
    .map(c => getCRLDistrubutionPoints(c))
    .reduce((acc, el) => acc.add(el), new Set())
  const crlsPromises = [...allCrls].map(url => fetch(url))
  const responses =  await Promise.all(crlsPromises)
  const crlsRaw = await Promise.all(responses.map(response => response.arrayBuffer()))
  const crls = crlsRaw.map(crl => new CertificateRevocationList({ schema: fromBER(crl).result }));

  const certificateChainValidationResult = await new CertificateChainValidationEngine({
    trustedCerts: [intelRootCA],
    certs: certificateChain.slice().reverse(),
    crls: crls
  }).verify()

  // Verify certificate chain
  if (!certificateChainValidationResult.result) {
    throw Error(`Failed to verify certificate chain.` + certificateChainValidationResult.resultMessage);
  }

  // Verify signature
  const signatureValidationResult = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" }
    },
    (await getPublicKey(certificateChain[0])),
    quote.quoteAuthData.qeReportBodySignature.createArrayBuffer(),
    quote.quoteAuthData.qeReportBody.signedData.createArrayBuffer()
  )
  
  if (!signatureValidationResult) {
    throw Error(`Failed to verify Report body signature`)
  }

  // Verify hash
  const hash = new Data(await crypto.subtle.digest(
    'SHA-256',
    Data.join([quote.quoteAuthData.attestationKey.raw, quote.qeAuthData]).createArrayBuffer())
  )

  if (!(hash.equals(quote.quoteAuthData.qeReportBody.reportData.slice(0, 32)))) {
      throw Error(`Could not verify hash, got (${hash.toHex()}) expected (${quote.quoteAuthData.qeReportBody.reportData.slice(0, 32).toHex()})`)
  }

  // Verify signature
  const quoteAuthSignature = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" }
    },
    quote.quoteAuthData.attestationKey.key,
    quote.quoteAuthData.signature.createArrayBuffer(),
    quote.signedData.createArrayBuffer()
  )


  // Verify quote signature
  if (!quoteAuthSignature) {
      throw Error(`Quote signature could not be verified.`)
  }

  // Verify unique ID
  if (MRENCLAVE && !Data.fromBase64(MRENCLAVE).equals(quote.reportBody.uniqueID)) {
    throw Error(`MRENCLAVE mismatch. got(${quote.reportBody.uniqueID.toBase64()}) expected (${MRENCLAVE})`);
  }

  // Verify signer ID
  if (signerID && !Data.fromBase64(signerID).equals(quote.reportBody.signerID)) {
    throw Error(`Signer ID mismatch. got(${quote.reportBody.signerID.toBase64()}) expected(${signerID})`);
  }

  // Verify product ID
  if (productID && !Data.fromBase64(productID).equals(quote.reportBody.productID)) {
    throw Error(`Product ID mismatch.`);
  }

  // Verify security version
  if (quote.quoteAuthData.qeReportBody.securityVersion < securityVersion) {
    throw Error(`Security version is out of date.`);
  }

  return quote;
};
