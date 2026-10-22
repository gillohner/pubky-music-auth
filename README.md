# pubky-music-auth

The return page for signing in to music services from a self-hosted Pubky music node.

Services only send a login back to an address registered in advance, and every self-hosted node has its own (often a private LAN address). So the project's service apps register one address, `https://gillohner.github.io/pubky-music-auth/callback`, and this page sends the browser on to the node that started the sign-in.

How it works:
- The node starts the sign-in with `state = <nonce>.<base64url of its callback URL>` and a PKCE challenge.
- The service redirects here with `code` and `state`. The page reads the node's callback URL from `state`, accepts only `http` and `https`, and forwards the browser there with every query parameter unchanged.
- The node checks the nonce and redeems the code with its PKCE verifier, which never leaves the node. A code that reaches any other address is useless.

The page has no server, stores nothing, loads nothing from elsewhere (its Content-Security-Policy allows only its own inline script) and sends no referrer.
