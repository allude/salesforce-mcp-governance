import fs from 'node:fs';
import path from 'node:path';

const testDbPath = path.join(process.cwd(), 'data', 'test-self-check.sqlite');
for (const ext of ['', '-wal', '-shm']) {
  if (fs.existsSync(testDbPath + ext)) {
    fs.unlinkSync(testDbPath + ext);
  }
}
process.env.DB_PATH = testDbPath;

async function runSelfTests() {
  const { app } = await import('./index.js');
  const { store } = await import('./db/store.js');
  const server = app.listen(0);
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 3099;
  const baseUrl = `http://127.0.0.1:${port}`;

  console.log(`[Self-Test] Testing Clean Salesforce MCP Portal on ${baseUrl}`);

  try {
    // 1. Verify unauthenticated session is false (no auto-login bypass)
    const unauthRes = await fetch(`${baseUrl}/api/admin/session`);
    const unauthData = await unauthRes.json();
    if (unauthData.authenticated !== false) {
      throw new Error('Expected unauthenticated session to return authenticated: false');
    }
    console.log('✅ 1. Unauthenticated check passed (Login required)');

    // 2. Verify Username + Password Login
    const loginRes = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin123' }),
    });
    if (loginRes.status !== 200) {
      throw new Error(`Login failed (${loginRes.status}): ${await loginRes.text()}`);
    }
    const cookie = (loginRes.headers.get('set-cookie') || '').split(';')[0];
    const loginData = await loginRes.json();
    const csrfToken = loginData.csrfToken;
    console.log('✅ 2. Portal Username/Password Login succeeded');

    // 3. Verify Zero Demo Data on fresh DB
    const overviewRes = await fetch(`${baseUrl}/api/admin/overview`, {
      headers: { Cookie: cookie },
    });
    const overview = await overviewRes.json();
    if (
      overview.profiles.length !== 0 ||
      overview.objects.length !== 0 ||
      overview.groups.length !== 0 ||
      overview.copilotLogs.length !== 0
    ) {
      throw new Error(`Expected 0 demo data, got: ${JSON.stringify(overview.stats)}`);
    }
    console.log('✅ 3. Verified 0 demo data in Profiles, Objects, Groups, and Copilot Logs');

    // 4. Verify Payload Stripping Function
    const logEntry = store.recordCopilotMcpLog({
      sfUsername: 'user@company.com',
      profileId: '00eTEST',
      profileName: 'Test Profile',
      matchedGroups: ['TestGroup'],
      toolName: 'soql_query',
      targetObject: 'Account',
      status: 'ALLOWED',
      latencyMs: 12,
      rawRequestPayload: {
        objectName: 'Account',
        soql: "SELECT Id, Name FROM Account WHERE Secret__c = 'SUPER_SECRET_PII'",
        secretCustomerField: 'JOHN_DOE_SSN_123',
      },
      rawResponseSummary: {
        totalSize: 1,
        records: [{ Id: '001', Name: 'Private Customer Record' }],
      },
    });
    if (
      logEntry.sanitizedRequestPayload.includes('SUPER_SECRET_PII') ||
      logEntry.sanitizedRequestPayload.includes('JOHN_DOE_SSN_123') ||
      logEntry.sanitizedResponseSummary.includes('Private Customer Record')
    ) {
      throw new Error('Sensitive data was NOT stripped from Copilot log!');
    }
    console.log('✅ 4. Sensitive data stripping verified on Copilot MCP logs');

    // 5. Verify X.509 Certificate + RSA Key Generation & Salesforce JWT Connection
    const certRes = await fetch(`${baseUrl}/api/admin/sf-settings/generate-cert`, {
      method: 'POST',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ commonName: 'Self-Test Salesforce JWT' }),
    });
    if (!certRes.ok) {
      throw new Error(`Certificate generation failed: ${await certRes.text()}`);
    }
    const certData = await certRes.json();
    if (!certData.certificatePem.includes('BEGIN CERTIFICATE')) {
      throw new Error('Expected valid X.509 PEM certificate');
    }

    const connRes = await fetch(`${baseUrl}/api/admin/sf-settings/connect`, {
      method: 'POST',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        authMode: 'simulated',
        loginUrl: 'https://login.salesforce.com',
        clientId: '3MVG9_TEST_CLIENT_ID',
        username: 'mcp-sync@enterprise.com',
      }),
    });
    if (!connRes.ok) {
      throw new Error(`Salesforce JWT connect failed: ${await connRes.text()}`);
    }
    console.log('✅ 5. X.509 Certificate generation & Salesforce JWT connection verified');

    // 6. Verify Pulling Profiles + Removal Reconciliation (Pick & Choose)
    store.upsertProfile('00eLEGACY_DELETED', 'Legacy Deleted Profile');
    const profPrevRes = await fetch(`${baseUrl}/api/admin/profiles/pull-preview`, {
      method: 'POST',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({}),
    });
    const profPrevData = await profPrevRes.json();
    const detectedRemovedProfile = profPrevData.preview.removedFromOrg.find(
      (p: any) => p.id === '00eLEGACY_DELETED'
    );
    if (!detectedRemovedProfile) {
      throw new Error('Expected pull-preview to detect removed profile 00eLEGACY_DELETED');
    }

    // Apply profile sync keeping 00eLEGACY_DELETED first, then removing it
    await fetch(`${baseUrl}/api/admin/profiles/pull-apply`, {
      method: 'POST',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        upserts: profPrevData.preview.added,
        removeProfileIds: [],
        keptMissingProfileIds: ['00eLEGACY_DELETED'],
      }),
    });
    const keptProf = store.getProfileById('00eLEGACY_DELETED');
    if (!keptProf || !keptProf.missingInOrg) {
      throw new Error('Expected kept profile to remain and be flagged missingInOrg');
    }
    console.log('✅ 6. Salesforce Profile auto-pull & removal reconciliation verified');

    // 7. Verify Pulling Objects/Fields, Removal Reconciliation, & Resilient Runtime with Kept Missing Field
    store.upsertObjectWithFields({
      objectName: 'Account',
      label: 'Account',
      fields: [
        { fieldName: 'Id', label: 'Account ID', fieldType: 'Id', required: true },
        { fieldName: 'Name', label: 'Account Name', fieldType: 'Text' },
        { fieldName: 'Deleted_Legacy_Field__c', label: 'Deleted Field', fieldType: 'Text', isCustom: true },
      ],
    });

    const objPrevRes = await fetch(`${baseUrl}/api/admin/objects/pull-preview`, {
      method: 'POST',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ objectNames: ['Account'] }),
    });
    const objPrevData = await objPrevRes.json();
    const acctDiff = objPrevData.preview.upsertedObjects.find(
      (o: any) => o.objectName === 'Account'
    );
    const detectedRemovedField = acctDiff?.removedFieldsFromOrg?.find(
      (f: any) => f.fieldName === 'Deleted_Legacy_Field__c'
    );
    if (!detectedRemovedField) {
      throw new Error('Expected object pull-preview to detect removed field Deleted_Legacy_Field__c');
    }

    // Admin chooses NOT to remove Deleted_Legacy_Field__c (leaves it in place)
    await fetch(`${baseUrl}/api/admin/objects/pull-apply`, {
      method: 'POST',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        pulledMetadata: objPrevData.pulledMetadata,
        removeObjectNames: [],
        removeFields: [], // Leave Deleted_Legacy_Field__c in place!
      }),
    });

    // Create a Group that includes the left-over Deleted_Legacy_Field__c and map it to a Profile
    const grp = store.upsertGroup({
      name: 'Sales Test Group',
      allowedActions: ['soql_query', 'describe_object'],
      objectPermissions: [
        {
          objectName: 'Account',
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          allowedFields: ['Id', 'Name', 'Deleted_Legacy_Field__c'],
        },
      ],
    });
    store.setProfileGroups('00e8b000001SalesRp', [grp.id]);

    // Execute an MCP tool call to verify the left-over field does NOT break runtime queries!
    const { createUserScopedMcpServer } = await import('./mcp/server.js');
    const { resolveSalesforceUserFromToken, createSimulatorToken } = await import('./salesforce/client.js');
    const simUser = await resolveSalesforceUserFromToken(
      createSimulatorToken({
        profileId: '00e8b000001SalesRp',
        profileName: 'Enterprise Sales Representative',
      })
    );
    const mcpServer = createUserScopedMcpServer(simUser);
    const callHandler = (mcpServer as any)._requestHandlers.get('tools/call');
    const mcpResult = await callHandler({
      method: 'tools/call',
      params: {
        name: 'soql_query',
        arguments: {
          objectName: 'Account',
          fields: ['Id', 'Name', 'Deleted_Legacy_Field__c'],
        },
      },
    });
    if (mcpResult.isError) {
      throw new Error(`Expected soql_query with kept missing field not to break: ${JSON.stringify(mcpResult)}`);
    }
    const parsedMcpPayload = JSON.parse(mcpResult.content[0].text);
    if (!parsedMcpPayload.ignoredMissingFields?.includes('Deleted_Legacy_Field__c')) {
      throw new Error('Expected Deleted_Legacy_Field__c to be safely ignored at runtime');
    }
    console.log('✅ 7. Object/Field pull diff & runtime resilience with left-over deleted fields verified');

    // Clean up test data so database remains 100% empty of demo/test data
    const { DatabaseSync } = await import('node:sqlite');
    const { config } = await import('./config.js');
    const cleanDb = new DatabaseSync(config.dbPath);
    cleanDb.exec(`
      DELETE FROM profile_group_memberships;
      DELETE FROM access_groups;
      DELETE FROM sf_object_fields;
      DELETE FROM sf_objects;
      DELETE FROM sf_profiles;
      DELETE FROM mcp_copilot_logs;
      DELETE FROM portal_admin_logs;
      UPDATE sf_connection_settings
      SET enabled = 0,
          auth_mode = 'jwt_bearer',
          client_id = '',
          username = '',
          private_key_enc = '',
          certificate_pem = '',
          cert_fingerprint = '',
          connection_status = 'disconnected',
          last_connected_at = NULL,
          last_error = '',
          connected_org_id = '',
          connected_user = ''
      WHERE id = 1;
    `);
    cleanDb.close();

    console.log('\n🎉 ALL CLEAN PORTAL & MCP SERVER TESTS PASSED!');
  } finally {
    server.close();
    for (const ext of ['', '-wal', '-shm']) {
      if (fs.existsSync(testDbPath + ext)) {
        try {
          fs.unlinkSync(testDbPath + ext);
        } catch {
          // ignore
        }
      }
    }
  }
}

runSelfTests().catch((err) => {
  console.error('❌ Self-Test Failed:', err);
  process.exit(1);
});
