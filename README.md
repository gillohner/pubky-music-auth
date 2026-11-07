# pubky-music-auth

The return page for signing in to music services from a self-hosted Pubky music node.

Services only send a login back to an address registered in advance, and every self-hosted node has its own (often a private LAN address). So the project's service apps register one address, `https://gillohner.github.io/pubky-music-auth/callback`, and this page sends the browser on to the node that started the sign-in.

How it works:
- The node starts the sign-in with `state = <nonce>.<base64url of its callback URL>` and a PKCE challenge.
- The service redirects here with `code` and `state`. The page first takes the code out of its own history entry, then reads the node's callback URL from `state` and forwards the browser there with every query parameter unchanged, but only when that address is on the browser's own network:
  - `localhost` and `*.localhost`, names ending in `.local` or `.home.arpa`;
  - loopback and private IPv4 addresses (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16) and 100.64/10 (Tailscale and other carrier-grade NAT), written as numbers;
  - IPv6 loopback, unique-local (fc00::/7) and link-local (fe80::/10) addresses, and IPv4-mapped ones whose IPv4 part is local.

  Any other address is refused, including every other DNS name (so a `*.ts.net` name too, since Funnel can make it public). A link with a user name or password, or a query over 4 KB, is refused as well.
- The node checks the nonce and redeems the code with its PKCE verifier, which never leaves the node.

Why only local addresses: the project's service apps are public clients, so this page can't tell a node's own sign-in from one started elsewhere with the same app. A node on an internet address uses the TIDAL code sign-in, or its own app with its secret (the service then returns to the node directly).

The page has no server, stores nothing, loads nothing from elsewhere (its Content-Security-Policy allows only its own inline script) and sends no referrer.

Test: `node --test test/callback.test.mjs` (no dependencies; also runs on every push and pull request).
