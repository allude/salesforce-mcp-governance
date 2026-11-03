import './helpers/env.js';
// The certificate serial is random, so a DER encoding bug in it only shows on some draws. These tests
// pin the serial to the awkward first bytes instead of waiting for one to come up.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { generateSelfSignedCertificateBundle, inspectCertificatePem } from '../src/salesforce/jwtConnection.js';

const SERIAL_BYTES = 12;
const serialStartingWith = (...first: number[]) =>
  Buffer.concat([Buffer.from(first), Buffer.alloc(SERIAL_BYTES - first.length, 0x11)]);

describe('generated certificate serials', () => {
  for (const [name, first, expectedHexStart] of [
    ['a leading zero byte', [0x00, 0x01], '0111'],
    ['the highest value a padded byte can hold', [0x00, 0x7f], '7F11'],
    ['several leading zero bytes', [0x00, 0x00, 0x00, 0x05], '0511'],
    ['zero bytes before a high bit', [0x00, 0x00, 0x80], '8011'],
    ['a high first bit', [0x80, 0x00], '800011'],
    ['no zero bytes', [0x7f, 0x00], '7F0011'],
  ] as const) {
    test(`${name} still gives a valid certificate`, (t) => {
      t.mock.method(crypto, 'randomBytes', () => serialStartingWith(...first));

      const bundle = generateSelfSignedCertificateBundle('Serial Test');

      const certificate = new crypto.X509Certificate(bundle.certificatePem);
      assert.ok(certificate.serialNumber.toUpperCase().startsWith(expectedHexStart), certificate.serialNumber);
      assert.ok(certificate.verify(crypto.createPublicKey(bundle.privateKeyPem)));
      assert.equal(inspectCertificatePem(bundle.certificatePem)?.fingerprintSha256, bundle.fingerprintSha256);
    });
  }
});
