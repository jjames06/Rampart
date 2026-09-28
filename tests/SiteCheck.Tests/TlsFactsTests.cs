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
