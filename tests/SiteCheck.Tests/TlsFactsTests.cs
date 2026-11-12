// CODEMAP FILE: tests/SiteCheck.Tests/TlsFactsTests.cs
// Product: Rampart (oli-site-check) — read-only public-surface hostname checker, public pin 1.9.0
// Role: Locks protocol labels and expiry-window copy.
// Called by: dotnet test.
// Calls: TlsFacts.
// Invariants: Labels only; Checker owns the handshake.
// Sisters: Bastion (bastion-hardening) hardens the local Windows PC. bastion-web is the public storefront and hosts /rampart plus the GitHub asset redirect. oli-web-kits client brochures should already 404 the probe paths this checker GETs.
// Map: docs/CODEMAP.md — read that file first for the run/load graph.

using SiteCheck.Core;

namespace SiteCheck.Tests;

public class TlsFactsTests
{
    [Fact]
    public void Flags_rsa_key_exchange_without_dhe()
    {
        Assert.True(TlsFacts.CipherLacksForwardSecrecy("TLS_RSA_WITH_AES_128_GCM_SHA256"));
        Assert.False(TlsFacts.CipherLacksForwardSecrecy("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
        Assert.False(TlsFacts.CipherLacksForwardSecrecy("TLS_AES_128_GCM_SHA256"));
    }

    [Fact]
    public void Flags_cbc_and_short_rsa()
    {
        Assert.True(TlsFacts.CipherUsesLegacyBulk("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
        Assert.False(TlsFacts.CipherUsesLegacyBulk("TLS_AES_128_GCM_SHA256"));
        Assert.True(TlsFacts.RsaKeyIsWeak("RSA", 1024));
        Assert.False(TlsFacts.RsaKeyIsWeak("RSA", 2048));
        Assert.False(TlsFacts.RsaKeyIsWeak("ECDSA", 256));
    }
}
