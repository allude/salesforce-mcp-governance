// Enrolls, replaces or removes a portal password account's authenticator app, from a shell on the
// server. Production requires an authenticator code for every password sign-in, so this is how a
// break-glass account gets one (or gets a new one after a lost phone).
//
//   npm run portal:totp -- <username>            enroll; refuses an account that already has one
//   npm run portal:totp -- <username> --replace  issue a new secret, replacing the current one
//   npm run portal:totp -- <username> --remove   remove it (production then refuses password sign-in)
//
// It opens the same database (DB_PATH) with the same APP_SECRET_KEY as the server; SQLite's WAL mode
// lets it run while the server is up. The secret is printed once, to the terminal only.
import { store } from '../db/store.js';
import { generateTotpSecret, totpProvisioningUri } from '../security/totp.js';

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--')));
const [requested] = args.filter((a) => !a.startsWith('--'));
const unknown = [...flags].filter((f) => f !== '--replace' && f !== '--remove');
if (!requested || unknown.length > 0 || (flags.has('--replace') && flags.has('--remove'))) {
  fail('Usage: npm run portal:totp -- <username> [--replace | --remove]');
}

const username = store.findPortalUsername(requested);
if (username === undefined) fail(`No portal user named '${requested}'.`);
const current = store.getPortalUserTotp(username);

if (flags.has('--remove')) {
  store.clearPortalUserTotp(username);
  store.recordPortalAdminLog({
    adminUsername: 'server-cli',
    authMethod: 'password',
    action: 'REMOVE_PORTAL_USER_TOTP',
    target: `Portal User: ${username}`,
    details: `Removed the authenticator of "${username}" from the server command line.`,
    ipAddress: '127.0.0.1',
    targetType: 'portal_user',
    targetId: username,
  });
  console.log(`Removed the authenticator of '${username}'.`);
  process.exit(0);
}

if (current && !flags.has('--replace')) {
  fail(`'${username}' already has an authenticator. Pass --replace to issue a new one.`);
}

const secret = generateTotpSecret();
store.setPortalUserTotp(username, secret);
// Sessions opened with the old authenticator end: whoever replaced it may be recovering from a lost device.
store.revokeAdminSessionsFor('local_bootstrap', username);
store.recordPortalAdminLog({
  adminUsername: 'server-cli',
  authMethod: 'password',
  action: 'ENROLL_PORTAL_USER_TOTP',
  target: `Portal User: ${username}`,
  details: `${current ? 'Replaced' : 'Enrolled'} the authenticator of "${username}" from the server command line.`,
  ipAddress: '127.0.0.1',
  targetType: 'portal_user',
  targetId: username,
});

console.log(`Authenticator ${current ? 'replaced' : 'enrolled'} for '${username}'.`);
console.log('Add it to an authenticator app now; it is not shown again.\n');
console.log(`  Setup key: ${secret.replace(/(.{4})/g, '$1 ').trim()}`);
console.log(`  URI:       ${totpProvisioningUri(secret, username)}\n`);
