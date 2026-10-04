# Tests

An end-to-end suite for `dcs`, for [agena](https://github.com/norayr/agena),
and for the Gemini implementation in Indy that both of them are built on.

```
make -f Makefile.fpc test        # or: python3 tests/run_tests.py
```

The suite builds its own document root and its own throwaway certificates, so
nothing here depends on files checked in. `openssl` and `python3` are the only
requirements beyond the two binaries.

Both binaries have to exist:

```
make -f Makefile.fpc                                    # builds build/dcs
make -C ../agena -f Makefile.fpc                      # builds agena
```

The default server checkout is `../agena`, beside the dcs checkout.
Override the locations with `DCS_BIN` and `AGENA_DIR`, or with
`AGENA_DIR=... make -f Makefile.fpc test`.

## What it covers

**protocol** — raw TLS sockets speaking the wire format, so the server side of
`TIdGeminiServer` is tested on its own rather than through a client that would
normalise away the thing being tested: the single-line `STATUS SP META` header,
CRLF-only framing, the 1024-byte request-line cap and its `59`s, userinfo and
fragment rejection, query pass-through, path traversal, and survival of
malformed requests.

**client** — the `dcs` binary against agena: statuses, metadata by extension,
CGI (environment, query, input, metadata headers, refusals), and that input is
held back until the server asks for it. The request grammar is `absolute-URI
CRLF` and carries no input field, so input reaches a server only as the query
string after a 1x; that is what the client tests hold it to.

**input** — the status 10 and 11 handshake, against a scripted listener, since
agena never asks for input and so cannot exercise it.

**files** — `--output`, `--save`, including the refusal to clobber an existing
file and the fallback naming for the site root.

**pins** — fingerprint format, that `--fingerprint` does not also fetch, that
coloned and plain hex pins both work, and that a wrong or foreign pin is refused.

**idents** — listing, ambiguous and unknown names, a certificate with no key, a
missing file, and that a named identity is resolved and reported.

**tls** — that TLS 1.3 and 1.2 are both negotiated, that a plaintext client
gets nothing, and what `RequireTLS13` does.

## Known defects

Two tests assert application behavior the current setup does not have. They
exercise agena's CGI handling and TLS configuration and are marked rather than
deleted, so they are reported on every run without failing the build:

```
agena never sees P.ExitCode, so a CGI that exits non-zero is served as 20 with
  whatever it printed first. The spec gives this its own status, 42.

agena accepts TLS 1.2 despite RequireTLS13=true. The application sets the
  TaurusTLS minimum, but the cause of the observed behavior is not yet
  established. Requiring 1.3 goes beyond Gemini's TLS 1.2 minimum.
```

Neither failure demonstrates a defect in the Indy Gemini/Spartan protocol
units. The TLS failure's root cause remains under investigation.

Run just those with `python3 tests/run_tests.py --xfail`. If one starts passing,
the run **fails**, so a fix cannot slip through unnoticed — drop the `xfail`
marker when that happens.

## Flags

```
-k GROUP     only groups whose name contains this, e.g. -k tls
--xfail      only the tests pinned to known defects
-v           print each test as it runs
--keep       leave the temporary directory behind for inspection
```

## Layout

`tests/run_tests.py` is one file on purpose. There is no framework: the whole
suite is a registry of decorated functions, so a test reads as the request it
makes and the assertion it makes about the reply.
