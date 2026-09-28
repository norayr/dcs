# dcs

A command line [Gemini](https://geminiprotocol.net) client, written in Free
Pascal, that fetches and posts gemtext and can log in with a client
certificate.

It prints the response rather than rendering gemtext: the status code, the
metadata, and then the body as it arrived. Text is left alone, so an emoji is
an emoji and a line break is a line break; only the characters a terminal
cannot show are escaped.

The name is short on purpose, so that it can be typed with one hand on a
Dvorak keyboard.

## Build

```sh
git clone --recurse-submodules git@github.com:norayr/dcs.git
cd dcs
make -f Makefile.fpc
```

The binary lands in `build/dcs`. There is no Lazarus project, because a plain
FPC build is all that is needed.

### TLS backends

The default is [TaurusTLS](https://github.com/TaurusTLS/TaurusTLS), vendored as a
submodule, which reaches TLS 1.3.

```sh
make -f Makefile.fpc              # TaurusTLS, TLS 1.3 (default)
make -f Makefile.fpc USE_TAURUS=0 # Indy's OpenSSL, TLS 1.2 at best
```

Both build. Only the TaurusTLS one is exercised here: the fallback compiles,
but at run time it needs the OpenSSL shared libraries from a built Indy package
on the library path, otherwise it reports `Could not load SSL library`.

## Usage

```sh
dcs [options] <url> [input]
```

| Option | |
| --- | --- |
| `--ident <cn\|mail\|fingerprint>` | log in with an identity |
| `--cert <file> --key <file>` | log in with a certificate pair |
| `--input <file>` | input from a file, or from standard input as `-` |
| `--output <file>` | save the body to a file, as it arrived |
| `--save` | save the body to a file named after the url |
| `--pin <sha256>` | require this exact server certificate |
| `--fingerprint` | print the server's SHA256 fingerprint and stop |
| `--idents` | list the identities available |

## Examples

The `example.org` transcripts below are illustrative: it is a placeholder host
and has no Gemini service. The others are real, from real servers.

Fetch a page:

```sh
$ dcs gemini://geminiprotocol.net
url:      gemini://geminiprotocol.net
status:   20  20 success
meta:     "text/gemini"

# Project Gemini

## Gemini in 100 words
```

Download a file. The body is written as it arrived, so the result is a real
gemtext file that a browser can open, or a real image:

```sh
$ dcs --output index.gmi gemini://geminiprotocol.net/
url:      gemini://geminiprotocol.net/
status:   20  20 success
meta:     "text/gemini"
wrote:    index.gmi  1184 bytes
```

`--save` picks the name from the url instead, so that a page you visit often
does not need a name typed out:

```sh
$ dcs --save gemini://geminiprotocol.net/
wrote:    geminiprotocol.net  1184 bytes
```

The name comes from the last segment of the path, keeping the extension, and the
query is left out. A path that ends in a slash has no name in it, so the host is
used instead. It will not overwrite: a name that is already taken is reported and
nothing is fetched, because two paths can end in the same name and one would
silently replace the other.

```sh
$ dcs --save gemini://geminiprotocol.net/
error:    would save to "geminiprotocol.net", which exists: name it with
          --output, or move it first
```

A response that is not a success is not written to a file at all. It is the
server's complaint rather than the document that was asked for, and a file left
behind under the url's name would stop the next attempt. The complaint is
printed instead.

Log in and download, for a page that is only served to you. The name after
`--ident` is invented here; use one of your own from `--idents`:

```sh
$ dcs --ident 4b1f0e9a --output notes.gmi gemini://example.org/u/ada/notes.gmi
identity: ada <ada@example.org>
url:      gemini://example.org/u/ada/notes.gmi
status:   20  20 success
meta:     "text/gemini; charset=utf-8"
wrote:    notes.gmi  412 bytes
```

Post a file, which is how a body longer than one line is sent:

```sh
$ dcs --ident 4b1f0e9a --input reply.gmi gemini://example.org/u/ada/post
identity: ada <ada@example.org>
url:      gemini://example.org/u/ada/post
status:   20  20 success
meta:     "text/gemini; charset=utf-8"
```

Post from standard input, so the text can come from anywhere:

```sh
$ printf '# hello\n' | dcs --ident 4b1f0e9a --input - gemini://example.org/u/ada/post
```

Input can also be a plain argument, for one short line:

```sh
$ dcs --ident 4b1f0e9a gemini://example.org/puzzle stone
```

## Logging in

Identities are certificate and key pairs under `~/.config/dcs/idents`, named
after the SHA256 fingerprint of the certificate. pishmish stores its
identities the same way, so a directory copied from one is picked up as it
stands. No key is read from this repository.

```sh
$ dcs --idents
identities in /home/ada/.config/dcs/idents:
  1eef2119ddc91595  maxwelld <maxwelld@example.org>  until 2037-01-01
  4b1f0e9a7c2d35b8  ada <ada@example.org>  until 2033-01-01
  6f8407b96498eff6  tilde
  80d009ad2a8fb9fa  ada
  f3f756552905e296  grigori
```

`--ident` takes a common name, a mail address, or a fingerprint, and tries them
from the most exact kind of match to the least. A query that still matches more
than one certificate is refused, with the candidates listed, rather than
resolved by guesswork:

```sh
$ dcs --ident ada gemini://example.org/
error:  "ada" matches 2 identities, so it is not clear which one to log in as:
  80d009ad2a8fb9fa  ada
  4b1f0e9a7c2d35b8  ada <ada@example.org>  until 2033-01-01
        name one of the above by its fingerprint
```

A server that wants a certificate may say so with a `60 certificate required`,
and one that has an account for you may show links nobody else can see. A
certificate pair named with `--cert` and `--key` works as well, and is useful
when the key is somewhere else.

## Certificates

Servers often have self-signed certificates, so the chain is not verified by
default. That is convenient for development and unacceptable for anything else,
so a certificate can be pinned:

```sh
$ FP=$(dcs --fingerprint gemini://127.0.0.1:1965/about.gmi)
$ dcs --pin "$FP" gemini://127.0.0.1:1965/about.gmi
url:      gemini://127.0.0.1:1965/about.gmi
status:   20  20 success
meta:     "text/gemini; charset=utf-8"

# about agena
```

`--fingerprint` connects once with verification overridden, which is the only
way to reach the certificate of a self-signed server, and prints the SHA256
fingerprint. Passing that back with `--pin` makes the client require that exact
certificate: a different one fails the handshake, whatever the chain says.
Fingerprints are compared with separators and case removed, so the colon
separated form and a bare hex string both work.

## Layout

```
src/dcs.lpr              command line handling and output
src/Units/GemClient.pas  request, status names, pinning, client certificate
src/Units/Identities.pas reading the certificates in ~/.config/dcs
```

The two backends expose certificate verification differently, so `GemClient`
adapts each of them to the same small `TCertificateWatch` object. TaurusTLS has
`OnVerifyCallback`, which sets a `Continue` flag; Indy has `OnVerifyPeer`,
which returns a boolean.

## Licence

Same terms as the Indy code it builds on; see that project for details.
