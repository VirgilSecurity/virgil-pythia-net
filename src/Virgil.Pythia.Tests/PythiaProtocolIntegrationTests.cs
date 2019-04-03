namespace Virgil.Pythia.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Linq;
    using System.Threading.Tasks;
    using FizzWare.NBuilder;
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Newtonsoft.Json;
    using NSubstitute;
    using Virgil.Crypto;
    using Virgil.Pythia.Client;
    using Virgil.Pythia.Crypto;
    using Virgil.Pythia.Exceptions;
    using Virgil.SDK.Common;
    using Virgil.SDK.Web.Authorization;
    using Virgil.SDK.Web.Connection;

    [TestClass]
    public class PythiaProtocolIntegrationTests
    {
        [TestMethod]
        public async Task YTC13()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = AppSettings.Get.AppId,
                ApiKey = AppSettings.Get.ApiKey,
                ApiKeyId = AppSettings.Get.ApiKeyId,
                ProofKeys = new List<string>() { AppSettings.Get.ProofKeys[0] },
                ApiURL = AppSettings.Get.ApiURL
            };

            var protocol = PythiaProtocol.Initialize(config);

            var bpp1 = await protocol.CreateBreachProofPasswordAsync("some password");
            await Task.Delay(TimeSpan.FromSeconds(1));

            var bpp2 = await protocol.CreateBreachProofPasswordAsync("some password");
            await Task.Delay(TimeSpan.FromSeconds(1));

            bpp1.Salt.Should().HaveCount(32);
            bpp2.Salt.Should().HaveCount(32);

            bpp1.DeblindedPassword.Should().HaveCountGreaterThan(300);
            bpp2.DeblindedPassword.Should().HaveCountGreaterThan(300);

            bpp1.Version.Should().Be(1);
            bpp2.Version.Should().Be(1);

            bpp1.Salt.Should().NotBeEquivalentTo(bpp2.Salt);
            bpp1.DeblindedPassword.Should().NotBeEquivalentTo(bpp2.DeblindedPassword);
        }

        [TestMethod]
        public async Task YTC14()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = AppSettings.Get.AppId,
                ApiKey = AppSettings.Get.ApiKey,
                ApiKeyId = AppSettings.Get.ApiKeyId,
                ProofKeys = AppSettings.Get.ProofKeys,
                ApiURL = AppSettings.Get.ApiURL
            };

            var protocol = PythiaProtocol.Initialize(config);

            var bpp = await protocol.CreateBreachProofPasswordAsync("some password");
            await Task.Delay(TimeSpan.FromSeconds(1));

            bpp.Version.Should().Be(3);
        }

        [TestMethod]
        public async Task YTC15()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = AppSettings.Get.AppId,
                ApiKey = AppSettings.Get.ApiKey,
                ApiKeyId = AppSettings.Get.ApiKeyId,
                ProofKeys = AppSettings.Get.ProofKeys.Skip(1),
                ApiURL = AppSettings.Get.ApiURL
            };

            var protocol = PythiaProtocol.Initialize(config);
            var bpp = await protocol.CreateBreachProofPasswordAsync("some password");
            await Task.Delay(TimeSpan.FromSeconds(2));

            var verifyResult1 = await protocol.VerifyBreachProofPasswordAsync("some password", bpp, false);
            await Task.Delay(TimeSpan.FromSeconds(2));

            var verifyResult2 = await protocol.VerifyBreachProofPasswordAsync("some password", bpp, true);
            await Task.Delay(TimeSpan.FromSeconds(2));

            var verifyResult3 = await protocol.VerifyBreachProofPasswordAsync("other password", bpp, false);
            await Task.Delay(TimeSpan.FromSeconds(2));

            var verifyResult4 = await protocol.VerifyBreachProofPasswordAsync("other password", bpp, true);
            await Task.Delay(TimeSpan.FromSeconds(2));

            verifyResult1.Should().BeTrue();
            verifyResult2.Should().BeTrue();
            verifyResult3.Should().BeFalse();
            verifyResult4.Should().BeFalse();
        }

        [TestMethod]
        public async Task YTC16()
        {
            var correnctPassword = "some password";
            var wrongPassword = "other password";

            var crypto = Substitute.For<IPythiaCrypto>();
            crypto.Blind(correnctPassword).Returns(new PythiaCrypto().Blind(correnctPassword));
            crypto.Blind(wrongPassword).Returns(new PythiaCrypto().Blind(wrongPassword));
            crypto.Deblind(Arg.Any<byte[]>(), Arg.Any<byte[]>())
                  .Returns((arg) => new PythiaCrypto().Deblind((byte[])arg[0], (byte[])arg[1]));
            crypto.GenerateSalt().Returns(new PythiaCrypto().GenerateSalt());
            crypto.Verify(Arg.Any<PythiaProofParams>()).Returns(true, false, false, false, false);

            var virgilCrypto = new VirgilCrypto();
            var signer = new VirgilAccessTokenSigner();

            var apiKey = virgilCrypto.ImportPrivateKey(Bytes.FromString(AppSettings.Get.ApiKey, StringEncoding.BASE64));
            var generator = new JwtGenerator(AppSettings.Get.AppId, apiKey, AppSettings.Get.ApiKeyId, TimeSpan.FromDays(1), signer);
            var jwt = generator.GenerateToken("PYTHIA-CLIENT");

            var connection = new ServiceConnection(AppSettings.Get.ApiURL);
            var tokenProvider = new ConstAccessTokenProvider(jwt);

            var client = new PythiaClient(connection, new NewtonsoftJsonSerializer());

            var protocol = new PythiaProtocol(client, crypto, tokenProvider, AppSettings.Get.ProofKeys.Skip(1));
            var bpp = await protocol.CreateBreachProofPasswordAsync(correnctPassword);
            await Task.Delay(TimeSpan.FromSeconds(2));

            var verifyResult1 = await protocol.VerifyBreachProofPasswordAsync(correnctPassword, bpp, false);
            verifyResult1.Should().BeTrue();
            await Task.Delay(TimeSpan.FromSeconds(2));

            Func<Task> verifyResult2 = async () => { await protocol.VerifyBreachProofPasswordAsync(correnctPassword, bpp, true); };
            verifyResult2.Should().Throw<Exception>();
            await Task.Delay(TimeSpan.FromSeconds(2));

            var verifyResult3 = await protocol.VerifyBreachProofPasswordAsync(wrongPassword, bpp, false);
            verifyResult3.Should().BeFalse();
            await Task.Delay(TimeSpan.FromSeconds(2));

            Func<Task> verifyResult4 = async () => { await protocol.VerifyBreachProofPasswordAsync(wrongPassword, bpp, true); };
            verifyResult4.Should().Throw<Exception>();
            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        [TestMethod]
        public async Task YTC17()
        {
            var config1 = new PythiaProtocolConfig
            {
                AppId = AppSettings.Get.AppId,
                ApiKey = AppSettings.Get.ApiKey,
                ApiKeyId = AppSettings.Get.ApiKeyId,
                ProofKeys = AppSettings.Get.ProofKeys.Take(2),
                ApiURL = AppSettings.Get.ApiURL
            };

            var protocol1 = PythiaProtocol.Initialize(config1);

            var config2 = new PythiaProtocolConfig
            {
                AppId = AppSettings.Get.AppId,
                ApiKey = AppSettings.Get.ApiKey,
                ApiKeyId = AppSettings.Get.ApiKeyId,
                ProofKeys = AppSettings.Get.ProofKeys
            };

            var protocol2 = PythiaProtocol.Initialize(config2);
            var bpp1 = await protocol1.CreateBreachProofPasswordAsync("some password");
            var bpp2 = protocol2.UpdateBreachProofPassword(AppSettings.Get.UpdateToken, bpp1);

            bpp1.Version.Should().Be(2);

            bpp2.Salt.Should().BeEquivalentTo(bpp1.Salt);
            bpp2.DeblindedPassword.Should().NotBeEquivalentTo(bpp1.DeblindedPassword);
            bpp2.Version.Should().Be(3);
        }

        [TestMethod]
        public async Task YTC18()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = AppSettings.Get.AppId,
                ApiKey = AppSettings.Get.ApiKey,
                ApiKeyId = AppSettings.Get.ApiKeyId,
                ProofKeys = AppSettings.Get.ProofKeys.Take(3),
                ApiURL = AppSettings.Get.ApiURL
            };

            var protocol = PythiaProtocol.Initialize(config);

            var bpp1 = await protocol.CreateBreachProofPasswordAsync("some password");
            Action result = () => protocol.UpdateBreachProofPassword(AppSettings.Get.UpdateToken, bpp1);

            result.Should().Throw<Exception>();
        }
    }
}