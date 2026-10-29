import './helpers/env.js';
// Covers src/db/importers.ts: the Profile CSV parser and the SFDX / Metadata API XML parser.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProfilesCsv, parseSfdxFilesToObjects } from '../src/db/importers.js';

const CLASSIC_INVOICE_OBJECT = `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <!-- <label>Commented Out</label> -->
    <compactLayouts>
        <fullName>Invoice_Compact</fullName>
        <fields>Name</fields>
        <label>Invoice Compact Layout</label>
    </compactLayouts>
    <deploymentStatus>Deployed</deploymentStatus>
    <fields>
        <fullName>Amount__c</fullName>
        <label>Amount</label>
        <required>true</required>
        <type>Currency</type>
    </fields>
    <fields>
        <fullName>Status__c</fullName>
        <label>Status</label>
        <type>Picklist</type>
        <valueSet>
            <valueSetDefinition>
                <value><fullName>Open</fullName><label>Open Value</label></value>
            </valueSetDefinition>
        </valueSet>
    </fields>
    <label>R&amp;D Invoice</label>
    <listViews><fullName>All</fullName><label>All Invoices</label></listViews>
    <nameField><label>Invoice Number</label><type>AutoNumber</type></nameField>
</CustomObject>`;

describe('parseSfdxFilesToObjects', () => {
  test('classic .object: the object label is the top-level <label>, not a compact layout, field or list view label', () => {
    const [invoice] = parseSfdxFilesToObjects([{ relativePath: 'objects/Invoice__c.object', content: CLASSIC_INVOICE_OBJECT }]);
    assert.equal(invoice.objectName, 'Invoice__c');
    assert.equal(invoice.label, 'R&D Invoice');
    assert.equal(invoice.isCustom, true);
  });

  test('classic .object: only top-level <fields> blocks become fields, with their own label, type and required flag', () => {
    const [invoice] = parseSfdxFilesToObjects([{ relativePath: 'objects/Invoice__c.object', content: CLASSIC_INVOICE_OBJECT }]);
    const byName = new Map(invoice.fields.map((f) => [f.fieldName, f]));
    assert.deepEqual([...byName.keys()].sort(), ['Amount__c', 'Id', 'Name', 'Status__c']);
    assert.deepEqual(byName.get('Amount__c'), { fieldName: 'Amount__c', label: 'Amount', fieldType: 'Currency', isCustom: true, required: true });
    // The picklist value's nested <label>Open Value</label> must not leak into the field label
    assert.equal(byName.get('Status__c')?.label, 'Status');
    assert.equal(byName.get('Status__c')?.fieldType, 'Picklist');
  });

  test('SFDX source format: object-meta label, field files under fields/, and Id + Name always present', () => {
    const objects = parseSfdxFilesToObjects([
      {
        relativePath: 'force-app/main/default/objects/Shipment__c/Shipment__c.object-meta.xml',
        content: `<CustomObject><compactLayouts><label>Shipment Compact</label></compactLayouts><label>Shipment</label></CustomObject>`,
      },
      {
        relativePath: 'force-app/main/default/objects/Shipment__c/fields/Carrier__c.field-meta.xml',
        content: `<?xml version="1.0"?><CustomField><fullName>Carrier__c</fullName><label>Carrier</label><type>Text</type></CustomField>`,
      },
    ]);
    assert.equal(objects.length, 1);
    assert.equal(objects[0].label, 'Shipment');
    assert.deepEqual(objects[0].fields.map((f) => f.fieldName).sort(), ['Carrier__c', 'Id', 'Name']);
  });

  test('standard object extended with only fields/ files is inferred from the folder name', () => {
    const [account] = parseSfdxFilesToObjects([
      { relativePath: 'objects\\Account\\fields\\Tier__c.field-meta.xml', content: '<CustomField><label>Tier</label><type>Picklist</type></CustomField>' },
    ]);
    assert.equal(account.objectName, 'Account');
    assert.equal(account.isCustom, false);
    const tier = account.fields.find((f) => f.fieldName === 'Tier__c');
    assert.deepEqual(tier, { fieldName: 'Tier__c', label: 'Tier', fieldType: 'Picklist', isCustom: true, required: false });
  });

  test('field files whose object cannot be determined are skipped instead of inventing an object', () => {
    const objects = parseSfdxFilesToObjects([
      { relativePath: 'Stray__c.field-meta.xml', content: '<CustomField><fullName>Stray__c</fullName></CustomField>' },
      { relativePath: 'objects/Loose__c.field-meta.xml', content: '<CustomField><fullName>Loose__c</fullName></CustomField>' },
    ]);
    assert.deepEqual(objects, []);
  });

  test('malformed entries are ignored rather than throwing', () => {
    const objects = parseSfdxFilesToObjects([
      {} as any,
      { relativePath: 42, content: 'x' } as any,
      { relativePath: 'objects/Case.object', content: '<CustomObject><label>Case</label></CustomObject>' },
    ]);
    assert.deepEqual(objects.map((o) => `${o.objectName}:${o.label}`), ['Case:Case']);
  });
});

describe('parseProfilesCsv', () => {
  test('header row, CRLF endings, BOM, blank lines, quoted commas and escaped quotes', () => {
    const csv = '﻿Id,Name\r\n00e000000000001AAA,"Sales, EMEA"\r\n\r\n"00e000000000002AAA","Say ""Hi"""\r\n';
    assert.deepEqual(parseProfilesCsv(csv), [
      { id: '00e000000000001AAA', name: 'Sales, EMEA' },
      { id: '00e000000000002AAA', name: 'Say "Hi"' },
    ]);
  });

  test('when only one header column is recognised, the other value comes from the other column', () => {
    assert.deepEqual(parseProfilesCsv('Name,SFID\nSystem Administrator,00e000000000007AAA'), [
      { id: '00e000000000007AAA', name: 'System Administrator' },
    ]);
    assert.deepEqual(parseProfilesCsv('Id,Label\n00e000000000008AAA,Read Only'), [
      { id: '00e000000000008AAA', name: 'Read Only' },
    ]);
  });

  test('header columns can be in any order and extra columns are ignored (sf data query export)', () => {
    assert.deepEqual(parseProfilesCsv('Name,Id,UserType\nSystem Administrator,00e000000000003AAA,Standard'), [
      { id: '00e000000000003AAA', name: 'System Administrator' },
    ]);
  });

  test('without a header the first two columns are id and name; rows missing a value are skipped', () => {
    assert.deepEqual(parseProfilesCsv('00e000000000004AAA,Read Only\n00e000000000005AAA,\n,Orphan Name'), [
      { id: '00e000000000004AAA', name: 'Read Only' },
    ]);
  });

  test('legacy single-quoted values and profile_id/profile_name headers are accepted', () => {
    assert.deepEqual(parseProfilesCsv("profile_id,profile_name\n'00e000000000006AAA','Custom: Support'"), [
      { id: '00e000000000006AAA', name: 'Custom: Support' },
    ]);
  });

  test('an empty document yields no rows', () => {
    assert.deepEqual(parseProfilesCsv('\n\r\n  \n'), []);
  });
});
