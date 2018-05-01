namespace Virgil.Pythia.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using FizzWare.NBuilder;
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using NSubstitute;
    using Virgil.Crypto.Pythia;

    using Virgil.Pythia.Client;
    using Virgil.Pythia.Crypto;
    using Virgil.Pythia.Exceptions;

    using Virgil.SDK.Common;
    using Virgil.SDK.Web.Authorization;

    [TestClass]
    public class PythiaProtocolTests
    {
        [TestMethod]
        public async Task CreateBreachProofPassword_Should_SelectProofKeyWithLatestVersion()
        {
            var password = "test_password";

            var crypto = Substitute.For<IPythiaCrypto>();
            crypto.Blind(password).Returns(new Tuple<byte[], byte[]>(GetRandom.Bytes(), GetRandom.Bytes()));
            crypto.GenerateSalt().Returns(GetRandom.Bytes());
            crypto.Verify(Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<byte[]>(),
                          Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<byte[]>()).Returns(true);

            var accessToken = Substitute.For<IAccessToken>();
            var provider = Substitute.For<IAccessTokenProvider>();
            provider.GetTokenAsync(null).Returns(Task.FromResult(accessToken));

            var client = Substitute.For<IPythiaClient>();
            var model = Builder<TransformResultModel>.CreateNew()
                .With(it => it.Proof = Builder<ProofModel>.CreateNew().Build())
                .Build();

            client.TransformPasswordAsync(Arg.Any<TransformModel>(), Arg.Any<string>()).Returns(Task.FromResult(model));

            var proofKeys = new[]
            {
                "PK.1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
                "PK.3.AwQv8oHsgsrOet//6kp8hsa8ZFEN0HqBS8ENze2A2VPhmtLUo3R+/Ig0lt/yYUzy8Q==",
                "PK.2.Aw/DlJjsqdED6pTCpIwqZmUZNT38F2ZvKtEBMVAIQJEamORuT++s65+B6MA3uNZ5kg=="
            };

            var protocol = new PythiaProtocol(client, crypto, provider, proofKeys);
            var result = await protocol.CreateBreachProofPasswordAsync(password);

            var tm = (TransformModel)client.ReceivedCalls().Single().GetArguments().First();
            tm.Version.Should().Be(3);
        }

        [TestMethod]
        public async Task CreateBreachProofPassword_Should_AlwaysRequestProofFromService()
        {
            var password = "test_password";

            var crypto = Substitute.For<IPythiaCrypto>();
            crypto.Blind(password).Returns(new Tuple<byte[], byte[]>(GetRandom.Bytes(), GetRandom.Bytes()));
            crypto.GenerateSalt().Returns(GetRandom.Bytes());
            crypto.Verify(Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<byte[]>(),
                          Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<byte[]>()).Returns(true);

            var accessToken = Substitute.For<IAccessToken>();
            var provider = Substitute.For<IAccessTokenProvider>();
            provider.GetTokenAsync(null).Returns(Task.FromResult(accessToken));

            var client = Substitute.For<IPythiaClient>();
            var model = Builder<TransformResultModel>.CreateNew()
                .With(it => it.Proof = Builder<ProofModel>.CreateNew().Build())
                .Build();

            client.TransformPasswordAsync(Arg.Any<TransformModel>(), Arg.Any<string>()).Returns(Task.FromResult(model));

            var proofKeys = new[] { "PK.1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==" };
            var protocol = new PythiaProtocol(client, crypto, provider, proofKeys);
            var result = await protocol.CreateBreachProofPasswordAsync(password);

            var tm = (TransformModel)client.ReceivedCalls().Single().GetArguments().First();
            tm.IncludeProof.Should().BeTrue();
        }
        
        [TestMethod]
        [ExpectedException(typeof(PythiaProofIsNotValidException))]
        public async Task CreateBreachProofPassword_Should_ThrowAnException_IfProofIsNotValid()
        {
            var password = "test_password";

            var crypto = Substitute.For<IPythiaCrypto>();
            crypto.Blind(password).Returns(new Tuple<byte[], byte[]>(GetRandom.Bytes(), GetRandom.Bytes()));
            crypto.GenerateSalt().Returns(GetRandom.Bytes());
            crypto.Verify(Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<byte[]>(), 
                          Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<byte[]>()).Returns(false);

            var accessToken = Substitute.For<IAccessToken>();
            var provider = Substitute.For<IAccessTokenProvider>();
            provider.GetTokenAsync(null).Returns(Task.FromResult(accessToken));

            var client = Substitute.For<IPythiaClient>();
            var model = Builder<TransformResultModel>.CreateNew()
                .With(it => it.Proof = Builder<ProofModel>.CreateNew().Build())
                .Build();
            
            client.TransformPasswordAsync(Arg.Any<TransformModel>(), Arg.Any<string>()).Returns(Task.FromResult(model));

            var proofKeys = new[] { "PK.1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==" };
            var protocol = new PythiaProtocol(client, crypto, provider, proofKeys);
            var result = await protocol.CreateBreachProofPasswordAsync(password);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeysAreNull()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId = "4cb31d32a58899fc968ac12573229789",
                ApiKey = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = null
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeysAreEmpty()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId = "4cb31d32a58899fc968ac12573229789",
                ApiKey = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = new string[] { }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfAppIdIsNullOrEmpty()
        {
            var config = new PythiaProtocolConfig
            {
                AppId     = string.Empty,
                ApiKeyId  = "4cb31d32a58899fc968ac12573229789",
                ApiKey    = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = new string[] { 
                    "PK.1.AgY1HeqcosokoAiZQ/vO28cubQej3BChFg51FkVXe3vGdCEAMiEUVhO0jPIE0bUGGA==" 
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfApiKeyIdIsNullOrEmpty()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId = string.Empty,
                ApiKey = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = new string[] {
                    "PK.1.AgY1HeqcosokoAiZQ/vO28cubQej3BChFg51FkVXe3vGdCEAMiEUVhO0jPIE0bUGGA=="
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfApiKeyIsNullOrEmpty()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId = "4cb31d32a58899fc968ac12573229789",
                ApiKey = string.Empty,
                ProofKeys = new string[] {
                    "PK.1.AgY1HeqcosokoAiZQ/vO28cubQej3BChFg51FkVXe3vGdCEAMiEUVhO0jPIE0bUGGA=="
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeyHasNotPrefixPK()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId = "4cb31d32a58899fc968ac12573229789",
                ApiKey = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = new[] {
                    "BGG.1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA=="
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeyHasNotVersion()
        {
            var config = new PythiaProtocolConfig
            {
                AppId = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId = "4cb31d32a58899fc968ac12573229789",
                ApiKey = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = new[] {
                    "PK.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA=="
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeyHasNotThreeSeporatingDots()
        {
            var config = new PythiaProtocolConfig
            {
                AppId     = "cc420fcbe7ec442359f7a9f37dd84ea3",
                ApiKeyId  = "4cb31d32a58899fc968ac12573229789",
                ApiKey    = "MC4CAQAwBQYDK2VwBCIEIOBZP2yyDaGzHnZB5+PWtsshs0goN2RCSSNEuBtlg2DN",
                ProofKeys = new[] {
                    "PK.1.test.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA=="
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task RegisterAsync_Should_ThrowAnException_IfGivenPasswordIsNullOrEmpty() 
        {
            var client    = Substitute.For<IPythiaClient>();
            var crypto    = Substitute.For<IPythiaCrypto>();
            var provider  = Substitute.For<IAccessTokenProvider>();
            var proofKeys = new[] { "PK.1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==" };

            var protocol = new PythiaProtocol(client, crypto, provider, proofKeys);
            var result = await protocol.CreateBreachProofPasswordAsync("");
        }
    }
}
