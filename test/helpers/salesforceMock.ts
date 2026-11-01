// Replaces globalThis.fetch for Salesforce hosts only, at the network boundary.
// Requests to 127.0.0.1 / localhost (the app under test) go to the real fetch.
export interface RecordedSalesforceCall {
  method: string;
  url: URL;
  authorization: string;
  body: unknown;
}

export interface FakeSalesforceUser {
  userId: string;
  organizationId: string;
  username: string;
  email?: string;
  profileId: string;
  profileName: string;
  instanceUrl?: string;
  /** When set, the `SELECT ... FROM User` profile lookup answers with this HTTP status instead. */
  userQueryStatus?: number;
}

export interface SalesforceMock {
  calls: RecordedSalesforceCall[];
  /** Registers a Bearer token that userinfo will accept for the given user. */
  addUser(token: string, user: FakeSalesforceUser): void;
  /** Overrides the canned records returned for non-User SOQL queries. */
  setQueryRecords(records: Array<Record<string, unknown>>): void;
  /** Calls whose host is not a Salesforce domain (should stay empty: SSRF guard). */
  nonSalesforceCalls: RecordedSalesforceCall[];
  reset(): void;
  restore(): void;
}

const isLocal = (url: URL) => ['127.0.0.1', 'localhost', '[::1]', '::1'].includes(url.hostname);
const isSalesforce = (url: URL) => /(^|\.)(salesforce\.com|force\.com)$/i.test(url.hostname);

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

export function installSalesforceMock(): SalesforceMock {
  const realFetch = globalThis.fetch;
  const users = new Map<string, FakeSalesforceUser>();
  let queryRecords: Array<Record<string, unknown>> = [
    { attributes: { type: 'Account' }, Id: '001000000000001AAA', Name: 'Private Customer Record' },
  ];
  const mock: SalesforceMock = {
    calls: [],
    nonSalesforceCalls: [],
    addUser(token, user) {
      users.set(token, user);
    },
    setQueryRecords(records) {
      queryRecords = records;
    },
    reset() {
      mock.calls.length = 0;
      mock.nonSalesforceCalls.length = 0;
    },
    restore() {
      globalThis.fetch = realFetch;
    },
  };

  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (isLocal(url) && !url.pathname.startsWith('/services/')) {
      return realFetch(input as any, init);
    }

    const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));
    const method = (init?.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    let body: unknown = undefined;
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    const call: RecordedSalesforceCall = { method, url, authorization: headers.get('authorization') || '', body };

    if (!isSalesforce(url)) {
      mock.nonSalesforceCalls.push(call);
      return json(404, { error: 'not a salesforce host' });
    }
    mock.calls.push(call);

    const token = call.authorization.replace(/^Bearer\s+/i, '');
    const user = users.get(token);
    if (!user) {
      return json(401, [{ errorCode: 'INVALID_SESSION_ID', message: 'Session expired or invalid' }]);
    }

    const instanceUrl = user.instanceUrl || 'https://acme.my.salesforce.com';
    if (url.pathname === '/services/oauth2/userinfo') {
      return json(200, {
        user_id: user.userId,
        organization_id: user.organizationId,
        preferred_username: user.username,
        email: user.email || user.username,
        name: user.username,
        // Real userinfo `profile` is the user's own page, not the Profile record
        profile: `${instanceUrl}/${user.userId}`,
        urls: { custom_domain: instanceUrl, rest: `${instanceUrl}/services/data/v{version}/` },
      });
    }

    const queryMatch = url.pathname.match(/^\/services\/data\/v[\d.]+\/query$/);
    if (queryMatch && method === 'GET') {
      const soql = url.searchParams.get('q') || '';
      if (/FROM User WHERE Id =/i.test(soql)) {
        if (user.userQueryStatus) {
          return json(user.userQueryStatus, [{ errorCode: 'INSUFFICIENT_ACCESS', message: 'User lookup refused' }]);
        }
        return json(200, {
          totalSize: 1,
          done: true,
          records: [{ Id: user.userId, Username: user.username, ProfileId: user.profileId, Profile: { Name: user.profileName } }],
        });
      }
      return json(200, { totalSize: queryRecords.length, done: true, records: queryRecords });
    }

    const sobjectMatch = url.pathname.match(/^\/services\/data\/v[\d.]+\/sobjects\/([A-Za-z0-9_]+)(?:\/([A-Za-z0-9]+))?$/);
    if (sobjectMatch) {
      const [, objectName, recordId] = sobjectMatch;
      if (method === 'POST' && !recordId) return json(201, { id: '001000000000NEWAAA', success: true, errors: [] });
      if ((method === 'PATCH' || method === 'DELETE') && recordId) return new Response(null, { status: 204 });
      if (method === 'GET' && recordId) {
        return json(200, { attributes: { type: objectName }, Id: recordId, Name: 'Private Customer Record' });
      }
    }

    return json(404, [{ errorCode: 'NOT_FOUND', message: `Mock has no route for ${method} ${url.pathname}` }]);
  }) as typeof fetch;

  return mock;
}
