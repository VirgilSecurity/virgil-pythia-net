namespace Virgil.Pythia.Tests
{
    using System;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    using Virgil.Crypto;
    using Virgil.SDK.Common;
    using Virgil.SDK.Web.Authorization;

    [TestClass]
    public class BrainKeyTests
    {
        [TestMethod]
        public async Task EncryptAndDecrypt_UsingBrainKeys()
        {
            Func<TokenContext, Task<string>> tokenCallback = (c) =>
            {
                var virgilCrypto = new VirgilCrypto();
                var signer = new VirgilAccessTokenSigner();

                var apiKey = virgilCrypto.ImportPrivateKey(
                    Bytes.FromString(AppSettings.Get.ApiKey, StringEncoding.BASE64));
                
                var generator = new JwtGenerator(AppSettings.Get.AppId, apiKey, 
                    AppSettings.Get.ApiKeyId, TimeSpan.FromDays(1), signer);
                
                var jwt = generator.GenerateToken("BRAINKEY_CLIENT");
                
                return Task.FromResult(jwt.ToString());
            };

            var brainKey = BrainKey.Initialize(tokenCallback);
            var keyPair1 = await brainKey.GenerateKeyPair("some password");
            await Task.Delay(TimeSpan.FromSeconds(2));
            var keyPair2 = await brainKey.GenerateKeyPair("some password");
            await Task.Delay(TimeSpan.FromSeconds(2));

            var crypto = new VirgilCrypto();
            var plaindata = GetRandom.Bytes(128);
            var chipherdata = crypto.SignThenEncrypt(plaindata, keyPair1.PrivateKey, keyPair2.PublicKey);
            var originaldata = crypto.DecryptThenVerify(chipherdata, keyPair2.PrivateKey, keyPair1.PublicKey);

            originaldata.Should().BeEquivalentTo(plaindata);
        }
    }
}
