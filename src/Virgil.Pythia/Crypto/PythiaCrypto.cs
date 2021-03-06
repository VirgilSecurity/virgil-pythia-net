﻿// Copyright (C) 2015-2018 Virgil Security Inc.
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

namespace Virgil.Pythia.Crypto
{
    using System;

    using Virgil.Crypto;
    using Virgil.Crypto.Foundation;
    using Virgil.Crypto.Pythia;
    using Virgil.CryptoAPI;

    using Virgil.SDK.Common;

    /// <summary>
    /// The <see cref="PythiaCrypto"/> provides a list of crypto methods that 
    /// provided 
    /// </summary>
    public class PythiaCrypto : IPythiaCrypto, IDisposable
    {
        private readonly VirgilPythia pythia;

        /// <summary>
        /// Initializes a new instance of the <see cref="PythiaCrypto"/> class.
        /// </summary>
        public PythiaCrypto()
        {
            this.pythia = new VirgilPythia();
            this.DefaultKeyPairType = KeyPairType.Default;
        }

        /// <summary>
        /// Gets or Sets the type of the key pair.
        /// </summary>
        public KeyPairType DefaultKeyPairType { get; set; }

        /// <summary>
        /// Blind the specified password.
        /// </summary>
        /// <returns>The blind.</returns>
        /// <param name="password">Password.</param>
        public BlindingResult Blind(string password)
        {
            var blindingResult = this.pythia.Blind(Bytes.FromString(password));

            return new BlindingResult
            {
                BlindedPassword = blindingResult.BlindedPassword(),
                BlindingSecret = blindingResult.BlindingSecret()
            };
        }

        public byte[] Deblind(byte[] transformedPassword, byte[] blindingSecret)
        {
            return this.pythia.Deblind(transformedPassword, blindingSecret);
        }

        public byte[] GenerateSalt(uint size = 32)
        {
            using(var random = new VirgilRandom(string.Empty))
            {
                return random.Randomize(size);
            }
        }

        public byte[] UpdateDeblindedPassword(byte[] deblindedPassword, byte[] updateToken)
        {
            return this.pythia.UpdateDeblindedWithToken(deblindedPassword, updateToken);
        }

        public bool Verify(PythiaProofParams parameters)
        {
            return this.pythia.Verify(
                parameters.TransformedPassword, 
                parameters.BlindedPassword,
                parameters.Tweak, 
                parameters.TransformationPublicKey, 
                parameters.ProofValueC, 
                parameters.ProofValueU);
        }

        public (IPublicKey, IPrivateKey) GenerateKeyPair(byte[] keyMaterial)
        {
            var crypto = new VirgilCrypto();
            var keyPair = crypto.GenerateKeys(this.DefaultKeyPairType, keyMaterial);

            return (keyPair.PublicKey, keyPair.PrivateKey);
        }

        public void Dispose()
        {  
            this.Dispose(true);  
            GC.SuppressFinalize(this);  
        }  

        protected virtual void Dispose(bool disposing)
        {  
            if (disposing)
            {  
                this.pythia?.Dispose();
            }  
        }
    }
}
