// The return page's script, run against a fake page: it forwards only a service's answer, only to
// a node's callback on the browser's own network and only with the sign-in's own parameters,
// removes the code from the history entry first, and its CSP hash matches. node --test
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
    'https://10.0.0.2/tidal/callback',
    'http://172.16.0.1/tidal/callback',
    'http://172.31.255.1/tidal/callback',
    'http://169.254.10.1/tidal/callback',
    'http://[::1]:7788/tidal/callback',
    'http://[fd00::1]/tidal/callback',
    'http://[fe80::1]/tidal/callback',
    'http://[::ffff:192.168.1.5]/tidal/callback',
    'http://box.local/tidal/callback',
    'http://box.local./tidal/callback',
    'http://box.home.arpa/tidal/callback',
    'http://odeion.localhost/tidal/callback',
    'http://100.101.102.103/tidal/callback',
    'http://0x7f.1/tidal/callback',
    'http://192.168.1.5:7788/spotify/callback',
    'http://192.168.1.5:7788/drives/google/callback',
    'http://192.168.1.5:7788/drives/onedrive/callback',
    'https://box.local/odeion/tidal/callback',
    'https://box.local/my_proxy/odeion-2/drives/google/callback',
    // Dot segments and a doubled slash resolve to the node's callback
    'http://192.168.1.5/apply.cgi/../tidal/callback',
    'http://192.168.1.5//tidal/callback',
  ]) {
    const r = forwarded(cb);
    assert.ok(r.replaced, `${cb} forwards`);
    const to = new URL(r.replaced);
    assert.equal(to.origin + to.pathname, new URL(cb).origin + new URL(cb).pathname, cb);
    assert.equal(to.searchParams.get('code'), 'abc', `${cb}: the code is passed on`);
    assert.equal(to.searchParams.get('state'), stateFor(cb), `${cb}: the state is passed on`);
    assert.equal(r.link.textContent, 'Continue to ' + new URL(cb).host);
    assert.deepEqual(r.history, ['/pubky-music-auth/callback/'], `${cb}: the code leaves the history entry`);
  }
});

test('refuses every other address', () => {
  for (const cb of [
    'https://example.com/tidal/callback',
    'http://0x7f000001.example.com/tidal/callback',
    'http://127.0.0.1.nip.io/tidal/callback',
    'http://10.0.0.1@evil.example/tidal/callback',
    'http://user:pw@127.0.0.1/tidal/callback',
    'http://[2001:db8::1]/tidal/callback',
    'http://[::ffff:8.8.8.8]/tidal/callback',
    'http://8.8.8.8/tidal/callback',
    'http://172.32.0.1/tidal/callback',
    'http://100.128.0.1/tidal/callback',
    'http://box.ts.net/tidal/callback',
    'http://localhost.example.com/tidal/callback',
    'javascript:alert(1)',
    'data:text/html,hi',
    'ftp://127.0.0.1/tidal/callback',
    // Parser tricks: octal, unspecified, IPv4-compatible / NAT64 / 6to4 IPv6, backslashes, two dots
    'http://010.0.0.1/tidal/callback',
    'http://0.0.0.0/tidal/callback',
    'http://[::]/tidal/callback',
    'http://[::7f00:1]/tidal/callback',
    'http://[64:ff9b::a00:1]/tidal/callback',
    'http://[2002:a00:1::]/tidal/callback',
    'http:\\\\evil.example\\@127.0.0.1/tidal/callback',
    'http://localhost../tidal/callback',
  ]) {
    const r = forwarded(cb);
    assert.equal(r.replaced, null, `${cb} is refused`);
    assert.equal(r.title, 'This sign-in link is not complete', cb);
    assert.equal(r.link, undefined, `${cb}: no link to follow`);
    assert.deepEqual(r.history, ['/pubky-music-auth/callback/'], `${cb}: the code leaves the history entry`);
  }
});

test('refuses a state without a node address, and an over-long query', () => {
  for (const search of ['?code=abc&state=nonce', '?code=abc', `?code=${'a'.repeat(5000)}&state=${stateFor('http://127.0.0.1/tidal/callback')}`]) {
    const r = run(search);
    assert.equal(r.replaced, null, search.slice(0, 40));
    assert.deepEqual(r.history, ['/pubky-music-auth/callback/']);
  }
});

test('the page allows exactly its own script', () => {
  const hash = createHash('sha256').update(script).digest('base64');
  assert.match(html, new RegExp(`script-src 'sha256-${hash.replace(/[+/=]/g, '\\$&')}'`));
});

const refused = (r, what) => {
  assert.equal(r.replaced, null, `${what} is refused`);
  assert.equal(r.title, 'This sign-in link is not complete', what);
  assert.equal(r.link, undefined, `${what}: no link to follow`);
  assert.deepEqual(r.history, ['/pubky-music-auth/callback/'], `${what}: the code leaves the history entry`);
};

test('refuses a local address that is not a node callback', () => {
  for (const cb of [
    // A router's page, or any other local path
    'http://192.168.1.1/apply.cgi',
    'http://192.168.1.1/cb',
    'http://192.168.1.1/',
    'http://192.168.1.1',
    'http://192.168.1.1/tidal/callback/',
    'http://192.168.1.1/tidal/callback/x',
    'http://192.168.1.1/tidal/callbackx',
    'http://192.168.1.1/xtidal/callback',
    'http://192.168.1.1/drives/callback',
    'http://192.168.1.1/drives/a/b/callback',
    'http://192.168.1.1/qobuz/callback',
    'http://192.168.1.1/drives/other/callback',
    'http://192.168.1.1/TIDAL/callback',
    // A prefix that could be a script with extra path, or carry parameters
    'http://192.168.1.1/apply.cgi/tidal/callback',
    'http://192.168.1.1/index.php/spotify/callback',
    'http://192.168.1.1/apply.cgi;reboot=1/tidal/callback',
    'http://192.168.1.1/x;jsessionid=EVIL/tidal/callback',
    'http://192.168.1.1/apply.cgi%3Freboot=1%26x=/tidal/callback',
    'http://192.168.1.1/a%2Fb/tidal/callback',
    'http://192.168.1.1/a:b/tidal/callback',
    'http://192.168.1.1/a@b/drives/google/callback',
    // The target's own query or fragment
    'http://192.168.1.1/tidal/callback?reboot=1',
    'http://192.168.1.1/tidal/callback?',
    'http://192.168.1.1/tidal/callback#x',
    'http://192.168.1.1/tidal/callback#',
    'http://192.168.1.1/apply.cgi?reboot=1&x=/tidal/callback',
    'http://192.168.1.1/apply.cgi#/tidal/callback',
  ]) refused(forwarded(cb), cb);
});

test('forwards only a service answer, with only the sign-in parameters', () => {
  const cb = 'http://192.168.1.5:7788/tidal/callback';
  const st = encodeURIComponent(stateFor(cb));
  // No code and no error: nothing to finish
  for (const search of [`?state=${st}`, `?state=${st}&reboot=1`, `?code=&state=${st}`, `?error=&state=${st}`, ''])
    refused(run(search), search || '(empty)');
  // Only the first code counts
  refused(run(`?code=&code=abc&state=${st}`), 'an empty first code');
  // An error (the user said no) goes on, so the node can say so
  const denied = new URL(run(`?error=access_denied&error_description=No&state=${st}`).replaced);
  assert.equal(denied.origin + denied.pathname, cb);
  assert.equal(denied.searchParams.get('error'), 'access_denied');
  assert.equal(denied.searchParams.get('error_description'), 'No');
  assert.equal(denied.searchParams.get('state'), stateFor(cb));
  // The services' own replies: extra keys stay behind, the sign-in's go on unchanged
  const google = new URL(run(`?code=4%2F0Ab&scope=email&authuser=0&prompt=consent&state=${st}`).replaced);
  assert.deepEqual([...google.searchParams.keys()].sort(), ['code', 'state']);
  assert.equal(google.searchParams.get('code'), '4/0Ab');
  const onedrive = new URL(run(`?error=access_denied&error_subcode=cancel&error_description=The+user+said+no&state=${st}`).replaced);
  assert.deepEqual([...onedrive.searchParams.keys()].sort(), ['error', 'error_description', 'state']);
  assert.equal(onedrive.searchParams.get('error_description'), 'The user said no');
  const ms = new URL(run(`?code=M.C5&session_state=s1&state=${st}`).replaced);
  assert.deepEqual([...ms.searchParams.keys()].sort(), ['code', 'state']);
  // Only code, state, error, error_description and iss; everything else stays behind
  const to = new URL(run(`?code=abc&state=${st}&iss=https%3A%2F%2Fauth.example&reboot=1&cmd=x`).replaced);
  assert.equal(to.origin + to.pathname, cb);
  assert.deepEqual([...to.searchParams.keys()].sort(), ['code', 'iss', 'state']);
  assert.equal(to.searchParams.get('iss'), 'https://auth.example');
});
