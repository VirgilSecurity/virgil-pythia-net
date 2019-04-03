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
    using System.Threading.Tasks;

    using Virgil.CryptoAPI;
    using Virgil.Pythia.Client;
    using Virgil.Pythia.Crypto;

    using Virgil.SDK;
    using Virgil.SDK.Web.Authorization;
    using Virgil.SDK.Web.Connection;

    public class BrainKey
    {
        private readonly IPythiaCrypto crypto;
        private readonly IPythiaClient client;
        private readonly IAccessTokenProvider tokenProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="PythiaProtocol"/> class.
        /// </summary>
        public BrainKey(IPythiaClient client, IPythiaCrypto pythiaCrypto, IAccessTokenProvider tokenProvider)
        {
            this.tokenProvider = tokenProvider;
            this.client = client;
            this.crypto = pythiaCrypto;
        }

        public async Task<BrainKeyPair> GenerateKeyPair(string brainKeyPassword, string brainKeyId = null) 
        {
            var blindingResult = this.crypto.Blind(brainKeyPassword);

            var generateSeedModel = new GenerateSeedModel
            {
                BrainKeyId = brainKeyId,
                BlindedPassword = blindingResult.BlindedPassword
            };

            var tokenContext = new TokenContext("pythia", "seed");
            var accessToken = await this.tokenProvider.GetTokenAsync(tokenContext);
            var seed = await this.client.GenerateSeedAsync(generateSeedModel, accessToken.ToString());

            var deblindedPassword = this.crypto.Deblind(seed.Seed, blindingResult.BlindingSecret);

            (IPublicKey publicKey, IPrivateKey privateKey) = this.crypto.GenerateKeyPair(deblindedPassword);
            return new BrainKeyPair(publicKey, privateKey);
        }

        public static BrainKey Initialize(Func<TokenContext, Task<string>> obtainTokenCallback,
                                          string ApiURL = null) 
        {
            var connection = new ServiceConnection(ApiURL ?? "https://api.virgilsecurity.com");
            var client = new PythiaClient(connection, Configuration.Serializer);
            var crypto = new PythiaCrypto();

            var tokenProvider = new CachingJwtProvider(obtainTokenCallback);
            var brainKey = new BrainKey(client, crypto, tokenProvider);

            return brainKey;
        }
    }
}
