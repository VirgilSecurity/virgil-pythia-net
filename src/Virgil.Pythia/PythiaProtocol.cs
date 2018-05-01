// Copyright (C) 2015-2018 Virgil Security Inc.
// 
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions 
// are met:
// 
//   (1) Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//   
//   (2) Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in
//   the documentation and/or other materials provided with the
//   distribution.
//   
//   (3) Neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived 
//   from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

namespace Virgil.Pythia
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    using Virgil.Crypto;

    using Virgil.Pythia.Client;
    using Virgil.Pythia.Crypto;
    using Virgil.Pythia.Exceptions;

    using Virgil.SDK.Common;
    using Virgil.SDK.Web.Authorization;
    using Virgil.SDK.Web.Connection;

    /// <summary>
    /// The <see cref="PythiaProtocol"/> class provides a list of methods that 
    /// allows for developers to protect their users passwords in case database
    /// has been stolen or compromised. 
    /// </summary>
    public class PythiaProtocol
    {
        private readonly IPythiaCrypto pythiaCrypto;
        private readonly IPythiaClient client;
        private readonly IAccessTokenProvider tokenProvider;

        private readonly ConcurrentDictionary<int, byte[]> proofKeys;

        /// <summary>
        /// Initializes a new instance of the <see cref="PythiaProtocol"/> class.
        /// </summary>
        public PythiaProtocol(IPythiaClient client, IPythiaCrypto pythiaCrypto, 
            IAccessTokenProvider tokenProvider, IEnumerable<string> proofKeys)
        {
            this.tokenProvider = tokenProvider;
            this.client = client;
            this.pythiaCrypto = pythiaCrypto;

            if (proofKeys == null && !proofKeys.Any())
            {
                throw new ArgumentException("No one Proof Key has been set");
            }

            this.proofKeys = new ConcurrentDictionary<int, byte[]>();

            foreach(var proofKey in proofKeys)
            {
                var parsedProofKey = this.TryParseProofKey(proofKey);
                this.proofKeys.TryAdd(parsedProofKey.Item1, parsedProofKey.Item2);
            }
        }

        /// <summary>
        /// Verifies the user's original password by specified breach-proof password.
        /// </summary>/// 
        /// <param name="originalPassword">The original user's password</param>
        /// <param name="breachProofPassword"></param>
        /// <returns>Returns true if password is valid, otherwise false.</returns>
        public async Task<bool> VerifyBreachProofPasswordAsync(string originalPassword,
            BreachProofPassword breachProofPassword, bool prove = false)
        {
            if (string.IsNullOrEmpty(originalPassword))
            {
                throw new ArgumentNullException(nameof(originalPassword));
            }

            if (breachProofPassword == null)
            {
                throw new ArgumentNullException(nameof(breachProofPassword));
            }

            var blindingResult = this.pythiaCrypto.Blind(originalPassword);

            var transformModel = new TransformModel
            {
                BlindedPassword = blindingResult.BlindedPassword,
                Salt = breachProofPassword.Salt,
                Version = breachProofPassword.Version,
                IncludeProof = prove
            };

            var token = await this.tokenProvider.GetTokenAsync(null).ConfigureAwait(false);

            var result = await this.client.TransformPasswordAsync(
                transformModel, token.ToString()).ConfigureAwait(false);

            if (prove) 
            {
                var proofKey = this.proofKeys[breachProofPassword.Version];
                var proofParams = new PythiaProofParams
                {
                    TransformedPassword = result.TransformedPassword,
                    TransformationPublicKey = proofKey,
                    BlindedPassword = blindingResult.BlindedPassword,
                    Tweak = breachProofPassword.Salt,
                    ProofValueC = result.Proof.ValueC,
                    ProofValueU = result.Proof.ValueU
                };

                if (!this.pythiaCrypto.Verify(proofParams))
                {
                    throw new PythiaProofIsNotValidException();
                }
            }

            var deblindedPassword = this.pythiaCrypto.Deblind(
                result.TransformedPassword, blindingResult.BlindingSecret);

            return deblindedPassword.SequenceEqual(breachProofPassword.DeblindedPassword);
        }

        /// <summary>
        /// Updates the user's breach-proof password by specified update token.
        /// </summary>
        /// <returns>The breach-proof password.</returns>
        /// <param name="breachProofPassword">Breach proof password.</param> 
        /// <param name="updateToken">Update token.</param>
        public BreachProofPassword UpdateBreachProofPassword(
            string updateToken, BreachProofPassword breachProofPassword)
        {
            if (string.IsNullOrEmpty(updateToken))
            {
                throw new ArgumentNullException(nameof(updateToken));
            }

            if (breachProofPassword == null)
            {
                throw new ArgumentNullException(nameof(breachProofPassword));
            }

            var parsedUpdateToken = this.TryParseUpdateToken(updateToken);

            if (breachProofPassword.Version == parsedUpdateToken.Item2)
            {
                throw new PythiaUpdatingException("This breach-proof password has already been updated");
            }

            if (breachProofPassword.Version != parsedUpdateToken.Item1)
            {
                throw new PythiaUpdatingException("This breach-proof password version does not match this update token");
            }

            var newDeblindedPassword = this.pythiaCrypto.UpdateDeblindedPassword(
                breachProofPassword.DeblindedPassword, parsedUpdateToken.Item3);

            return new BreachProofPassword
            {
                DeblindedPassword = newDeblindedPassword,
                Version = parsedUpdateToken.Item2,
                Salt = breachProofPassword.Salt
            };
        }

        /// <summary>
        /// Creates a new breach-proof password for specified user's password.
        /// </summary>
        /// <param name="password">The user's password.</param>
        public async Task<BreachProofPassword> CreateBreachProofPasswordAsync(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var blindingResult = this.pythiaCrypto.Blind(password);
            var currentVersion = this.proofKeys.Keys.Max();
            var currentProofKey = this.proofKeys[currentVersion];

            var salt = this.pythiaCrypto.GenerateSalt();

            var transformModel = new TransformModel
            {
                BlindedPassword = blindingResult.BlindedPassword,
                Salt = salt,
                Version = currentVersion,
                IncludeProof = true
            };

            var token = await this.tokenProvider.GetTokenAsync(null).ConfigureAwait(false);

            var result = await this.client.TransformPasswordAsync(
                transformModel, token.ToString()).ConfigureAwait(false);

            var proofParams = new PythiaProofParams
            {
                TransformedPassword = result.TransformedPassword,
                TransformationPublicKey = currentProofKey,
                BlindedPassword = blindingResult.BlindedPassword,
                Tweak = salt,
                ProofValueC = result.Proof.ValueC,
                ProofValueU = result.Proof.ValueU
            };

            if (!this.pythiaCrypto.Verify(proofParams))
            {
                throw new PythiaProofIsNotValidException();
            }

            var deblindedPassword = this.pythiaCrypto.Deblind(
                result.TransformedPassword, blindingResult.BlindingSecret);

            return new BreachProofPassword 
            {
                DeblindedPassword = deblindedPassword, 
                Salt = salt, 
                Version = currentVersion
            };
        }

        private Tuple<int, byte[]> TryParseProofKey(string proofKey)
        {
            var keyParts = proofKey.Split('.');

            if (keyParts.Count() == 3
                && keyParts[0].Equals("pk", StringComparison.CurrentCultureIgnoreCase)
                && !string.IsNullOrWhiteSpace(keyParts[2]))
            {
                if (int.TryParse(keyParts[1], out int verson))
                {
                    var keyValue = Bytes.FromString(keyParts[2], StringEncoding.BASE64);
                    return new Tuple<int, byte[]>(verson, keyValue);
                }
            }

            throw new ArgumentException($"Incorrect Proof Key format");
        }

        private Tuple<int, int, byte[]> TryParseUpdateToken(string updateToken)
        {
            var tokenParts = updateToken.Split('.');

            if (tokenParts.Count() == 4
                && tokenParts[0].Equals("ut", StringComparison.CurrentCultureIgnoreCase)
                && !string.IsNullOrWhiteSpace(tokenParts[3]))
            {
                if (int.TryParse(tokenParts[1], out int oldVerson) &&
                    int.TryParse(tokenParts[2], out int newVerson))
                {
                    var keyValue = Bytes.FromString(tokenParts[3], StringEncoding.BASE64);
                    return new Tuple<int, int, byte[]>(oldVerson, newVerson, keyValue);
                }
            }

            throw new ArgumentException($"Incorrect Update Token format");
        }

        public static PythiaProtocol Initialize(PythiaProtocolConfig config)
        {
            if (config.ProofKeys == null || !config.ProofKeys.Any())
            {
                throw new ArgumentException(
                    $"{nameof(config.ProofKeys)} value cannot be null or empty");
            }

            if (string.IsNullOrWhiteSpace(config.AppId))
            {
                throw new ArgumentException(
                    $"{nameof(config.AppId)} value cannot be null or empty");
            }

            if (string.IsNullOrWhiteSpace(config.ApiKeyId))
            {
                throw new ArgumentException(
                    $"{nameof(config.ApiKeyId)} value cannot be null or empty");
            }

            if (string.IsNullOrWhiteSpace(config.ApiKey))
            {
                throw new ArgumentException(
                    $"{nameof(config.ApiKey)} value cannot be null or empty");
            }

            var crypto = new VirgilCrypto();
            var signer = new VirgilAccessTokenSigner();

            var apiKey = crypto.ImportPrivateKey(
                Bytes.FromString(config.ApiKey, StringEncoding.BASE64));

            var generator = new JwtGenerator(config.AppId, apiKey, 
                config.ApiKeyId, TimeSpan.FromDays(1), signer);
            
            var jwt = generator.GenerateToken("PYTHIA-CLIENT");

            var connection = new ServiceConnection(config.ApiURL);
            var tokenProvider = new ConstAccessTokenProvider(jwt);

            var client = new PythiaClient(connection, new NewtonsoftJsonSerializer());
            var pythiaCrypto = new PythiaCrypto();

            var protocol = new PythiaProtocol(client, pythiaCrypto, 
                tokenProvider, config.ProofKeys);
            
            return protocol;
        }
    }
}
