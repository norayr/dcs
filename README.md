# gem

A command line [Gemini](https://geminiprotocol.net) client, written in Free
Pascal on top of Indy's `TIdGemini`.

It exists mainly to test servers under development, so it prints the raw
response rather than rendering gemtext: the status code, the metadata, and the
body with control characters made visible.

## Build

Indy and TaurusTLS are vendored as submodules and pinned to known-good commits.

```sh
git clone --recurse-submodules <this repo>
cd gem
make -f Makefile.fpc
```

`build/gem` is the result. There is no Lazarus project, because a plain FPC
build is all that is needed.

### TLS backends

Indy's own OpenSSL handler is limited to the TLS 1.0/1.1 range that its
bundled OpenSSL supports. To get TLS 1.3, the client is built against
[TaurusTLS](https://github.com/TaurusTLS/TaurusTLS) instead, which provides a
drop-in `IOHandler`.

```sh
make -f Makefile.fpc              # TaurusTLS, TLS 1.3 (default)
make -f Makefile.fpc USE_TAURUS=0 # Indy's OpenSSL, TLS 1.2 at best
```

Both backends build. Only the TaurusTLS one is exercised here: the fallback
compiles, but at run time it needs the OpenSSL shared libraries from a built
Indy package on the library path, otherwise it reports
`Could not load SSL library`.

## Usage

```sh
gem <url>                 # fetch and print
gem <url> <input>         # fetch, sending gemtext input
gem --fingerprint <url>   # print the server's SHA256 certificate fingerprint
gem --pin <sha256> <url>  # fetch, trusting only that certificate
```

For example:

```sh
$ gem gemini://127.0.0.1/about.gmi
url:    gemini://127.0.0.1/about.gmi
status: 20  20 success
meta:   "text/gemini; charset=utf-8"
body:   # about agena\n\n=> / agena\n
```

`\n` and `\r` in the body are escapes rather than real line breaks, so that a
response stays on one line and control characters stay visible.

### Certificates

Servers under test usually have self-signed certificates, so the client does
not verify the chain by default. That is convenient for development and
unacceptable for anything else, so pinning is available:

```sh
$ FP=$(gem --fingerprint gemini://127.0.0.1/about.gmi)
$ gem --pin "$FP" gemini://127.0.0.1/about.gmi
```

`--fingerprint` connects once with verification overridden, which is the only
way to reach the certificate of a self-signed server, and prints the SHA256
fingerprint. Passing that back with `--pin` makes the client require that exact
certificate: a different one fails the handshake, whatever the chain says.

Fingerprints are compared with separators and case removed, so the colon
separated form printed above and a bare hex string both work.

## Layout

```
src/gem.lpr            command line handling and output
src/Units/GemClient.pas  request, status names, pinning
```

The two backends expose certificate verification differently, so `GemClient`
adapts each of them to the same small `TCertificateWatch` object. TaurusTLS
has `OnVerifyCallback`, which sets a `Continue` flag; Indy has `OnVerifyPeer`,
which returns a boolean.

## Licence

Same terms as the Indy code it builds on; see that project for details.
