namespace Virgil.Pythia.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using NSubstitute;
    using Virgil.Crypto.Pythia;
    using Virgil.Pythia.Client;
    using Virgil.Pythia.Crypto;
    using Virgil.SDK.Common;
    using Virgil.SDK.Web.Authorization;

    [TestClass]
    public class PythiaProtocolTests
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeysAreNull()
        {
            PythiaProtocol.Initialize(new PythiaProtocolConfig { ProofKeys = null });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeysAreEmpty()
        {
            PythiaProtocol.Initialize(new PythiaProtocolConfig { ProofKeys = new string[] { } });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfAppIdIsNullOrEmpty()
        {
            PythiaProtocol.Initialize(new PythiaProtocolConfig { AppId = string.Empty });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfApiKeyIdIsNullOrEmpty()
        {
            PythiaProtocol.Initialize(new PythiaProtocolConfig { ApiKeyId = string.Empty });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfApiKeyIsNullOrEmpty()
        {
            PythiaProtocol.Initialize(new PythiaProtocolConfig { ApiKey = string.Empty });
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeyHasNotPrefixPK()
        {
            var config = new PythiaProtocolConfig
            {
                ProofKeys = new[] {
                    "pk.v1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
                    "v2.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA=="
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
                ProofKeys = new[] {
                    "pk.v1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
                    "pk.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA=="
                }
            };

            PythiaProtocol.Initialize(config);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Initialize_Should_ThrowAnException_IfProofKeyHasMoreOrLessThanThreeSeporatingDots()
        {
            var config = new PythiaProtocolConfig
            {
                AppId     = "cc420fcbe7ec44569f7a9f37dd834ea3",
                ApiKeyId  = "4cb31d50a58899fc968ac12173329789",
                ApiKey    = "MC4CAQAwBQYDK2VwBCIEIE8rqq46Ic1YViuefZjnGL0nC7nQVf/HR/oRhJdiJTyT",
                ProofKeys = new[] {
                    "pk.v1.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA==",
                    "pk.v1.test.AgwhFXaYR7EWiTxeCCj269+cZKcRiT7x2Ifbyi4HrMnpSCapaoUzoK8rIJSNJC++jA=="
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
            var result = await protocol.CreateCipherHashAsync("");
        }

        [TestMethod]
        public async Task Test()
        {
            var config = new PythiaProtocolConfig
            {
                AppId    = "cc420fcbe7ec44569f7a9f37dd834ea3",
                ApiKeyId = "4cb31d50a58899fc968ac12173329789",
                ApiKey   = "MC4CAQAwBQYDK2VwBCIEIE8rqq46Ic1YViuefZjnGL0nC7nQVf/HR/oRhJdiJTyT",
                ProofKeys = new[] {
                    "PK.1.AgY1HeqcosokoAiZQ/vO28cubQej3CAhFg51FkVXe3vGdCEAMiEUVhO0jPIE0dCPGA=="
                }
            };

            var protocol = PythiaProtocol.Initialize(config);
            await protocol.CreateCipherHashAsync("bugaga");
        }
    }
}
