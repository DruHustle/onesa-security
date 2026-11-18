# Linux inventory collector (development preview)

Reads `/etc/machine-id` (only a SHA-256-derived opaque reference is sent), hostname and platform family, and posts an **actual** inventory snapshot to the Onesa Security API. Requires Python 3.11+, HTTPS, a pre-enrolled, short-lived collector credential stored in a file mode `0600`. Use only on machines where monitoring is authorized.

```sh
python3 collector.py --api https://security-api.example.test --credential-file /private/path/collector.token
```

No root privilege required. This is not the native endpoint protection agent described in the product roadmap. It does not offer OS event subscriptions, offline buffering, signed updates, tamper protection, mutual TLS client identity, automatic patching, endpoint isolation, or Windows/macOS support. By design, the production API refuses collector writes until a trusted ingress establishes mTLS and passes a verified ASGI scope; this preview does not provide client certificates. Test only against a local nonproduction API explicitly configured with `COLLECTOR_REQUIRE_MTLS=false` inside an isolated network.
