// The return page's script, run against a fake page: it forwards only to a node on the
// browser's own network, removes the code from the history entry first, and its CSP hash
// matches. node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';

const html = readFileSync(new URL('../callback/index.html', import.meta.url), 'utf8');
// Everything between the tags, as the browser hashes it for the CSP (the newline after <script> too)
const script = html.slice(html.indexOf('<script>') + '<script>'.length, html.indexOf('</script>'));

const stateFor = (callback) => 'nonce.' + Buffer.from(callback, 'utf8').toString('base64url');

function run(search) {
  const els = { title: { textContent: '' }, text: { textContent: '', children: [], appendChild(c) { this.children.push(c); } } };
  const page = { replaced: null, history: [] };
  const context = {
    location: { search, pathname: '/pubky-music-auth/callback/', replace: (u) => { page.replaced = u; } },
    history: { replaceState: (_s, _t, u) => page.history.push(u) },
    document: { getElementById: (id) => els[id], createElement: () => ({ href: '', textContent: '' }) },
    URL, URLSearchParams, atob, escape, decodeURIComponent,
  };
  vm.runInNewContext(script, context);
  return { ...page, title: els.title.textContent, link: els.text.children[0] };
}

const forwarded = (callback) => run(`?code=abc&state=${encodeURIComponent(stateFor(callback))}`);

test('forwards to a node on the browser\'s own network', () => {
  for (const cb of [
    'http://127.0.0.1:7788/tidal/callback',
    'http://localhost:7788/tidal/callback',
    'http://192.168.1.5/v1/sources/tidal/callback',
    'https://10.0.0.2/cb',
    'http://172.16.0.1/cb',
    'http://172.31.255.1/cb',
    'http://169.254.10.1/cb',
    'http://[::1]:7788/cb',
    'http://[fd00::1]/cb',
    'http://[fe80::1]/cb',
    'http://[::ffff:192.168.1.5]/cb',
    'http://box.local/cb',
    'http://box.local./cb',
    'http://box.home.arpa/cb',
    'http://odeion.localhost/cb',
    'http://100.101.102.103/cb',
    'http://0x7f.1/cb',
  ]) {
    const r = forwarded(cb);
    assert.ok(r.replaced, `${cb} forwards`);
    const to = new URL(r.replaced);
    assert.equal(to.origin + to.pathname, new URL(cb).origin + new URL(cb).pathname, cb);
    assert.equal(to.searchParams.get('code'), 'abc', `${cb}: every parameter is passed on`);
    assert.equal(r.link.textContent, 'Continue to ' + new URL(cb).host);
    assert.deepEqual(r.history, ['/pubky-music-auth/callback/'], `${cb}: the code leaves the history entry`);
  }
});

test('refuses every other address', () => {
  for (const cb of [
    'https://example.com/cb',
    'http://0x7f000001.example.com/cb',
    'http://127.0.0.1.nip.io/cb',
    'http://10.0.0.1@evil.example/cb',
    'http://user:pw@127.0.0.1/cb',
    'http://[2001:db8::1]/cb',
    'http://[::ffff:8.8.8.8]/cb',
    'http://8.8.8.8/cb',
    'http://172.32.0.1/cb',
    'http://100.128.0.1/cb',
    'http://box.ts.net/cb',
    'http://localhost.example.com/cb',
    'javascript:alert(1)',
    'data:text/html,hi',
    'ftp://127.0.0.1/cb',
    // Parser tricks: octal, unspecified, IPv4-compatible / NAT64 / 6to4 IPv6, backslashes, two dots
    'http://010.0.0.1/cb',
    'http://0.0.0.0/cb',
    'http://[::]/cb',
    'http://[::7f00:1]/cb',
    'http://[64:ff9b::a00:1]/cb',
    'http://[2002:a00:1::]/cb',
    'http:\\\\evil.example\\@127.0.0.1/cb',
    'http://localhost../cb',
  ]) {
    const r = forwarded(cb);
    assert.equal(r.replaced, null, `${cb} is refused`);
    assert.equal(r.title, 'This sign-in link is not complete', cb);
    assert.equal(r.link, undefined, `${cb}: no link to follow`);
    assert.deepEqual(r.history, ['/pubky-music-auth/callback/'], `${cb}: the code leaves the history entry`);
  }
});

test('refuses a state without a node address, and an over-long query', () => {
  for (const search of ['?code=abc&state=nonce', '?code=abc', `?code=${'a'.repeat(5000)}&state=${stateFor('http://127.0.0.1/cb')}`]) {
    const r = run(search);
    assert.equal(r.replaced, null, search.slice(0, 40));
    assert.deepEqual(r.history, ['/pubky-music-auth/callback/']);
  }
});

test('the page allows exactly its own script', () => {
  const hash = createHash('sha256').update(script).digest('base64');
  assert.match(html, new RegExp(`script-src 'sha256-${hash.replace(/[+/=]/g, '\\$&')}'`));
});
