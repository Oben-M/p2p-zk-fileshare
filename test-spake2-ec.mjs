// Standalone verification: run this with `node test-spake2-ec.mjs`
// Confirms matching codes derive identical keys, and mismatched codes
// fail cleanly -- before trusting this in the actual app.
import { Spake2ECParty } from './public/spake2-ec-test.mjs';

const code = '123-456-789';

const a = new Spake2ECParty('A');
const b = new Spake2ECParty('B');
const msgA = await a.start(code);
const msgB = await b.start(code);
const resA = await a.finish(msgB);
const resB = await b.finish(msgA);

console.log('Matching-code test:');
console.log('  keys equal:', Buffer.from(resA.sessionKey).equals(Buffer.from(resB.sessionKey)));
console.log('  A confirms B:', await a.verifyPeerConfirmation(resB.confirmTagHex));
console.log('  B confirms A:', await b.verifyPeerConfirmation(resA.confirmTagHex));
console.log('  key (hex):', Buffer.from(resA.sessionKey).toString('hex'));

const a2 = new Spake2ECParty('A');
const b2 = new Spake2ECParty('B');
const m2a = await a2.start('111-111-111');
const m2b = await b2.start('222-222-222');
const r2a = await a2.finish(m2b);
const r2b = await b2.finish(m2a);

console.log('\nMismatched-code test:');
console.log('  keys equal (should be false):', Buffer.from(r2a.sessionKey).equals(Buffer.from(r2b.sessionKey)));
console.log('  confirm (should be false):', await a2.verifyPeerConfirmation(r2b.confirmTagHex));
