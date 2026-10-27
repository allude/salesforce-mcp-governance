import { app } from './index.js';
import { store } from './db/store.js';

async function runSelfTests() {
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

    // Clean up test log so database remains 100% empty of demo/test data
    const { DatabaseSync } = await import('node:sqlite');
    const { config } = await import('./config.js');
    const cleanDb = new DatabaseSync(config.dbPath);
    cleanDb.exec('DELETE FROM mcp_copilot_logs; DELETE FROM portal_admin_logs;');
    cleanDb.close();

    console.log('\n🎉 ALL CLEAN PORTAL & MCP SERVER TESTS PASSED!');
  } finally {
    server.close();
  }
}

runSelfTests().catch((err) => {
  console.error('❌ Self-Test Failed:', err);
  process.exit(1);
});
