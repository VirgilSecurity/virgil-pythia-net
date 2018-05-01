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

namespace Virgil.Pythia.Crypto
{
    using System;

    using Virgil.Crypto.Foundation;
    using Virgil.Crypto.Pythia;

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
        }

        /// <summary>
        /// Blind the specified password.
        /// </summary>
        /// <returns>The blind.</returns>
        /// <param name="password">Password.</param>
        public Tuple<byte[], byte[]> Blind(string password)
        {
            var blindingResult = this.pythia.Blind(Bytes.FromString(password));

            return new Tuple<byte[], byte[]>(
                blindingResult.BlindedPassword(), blindingResult.BlindingSecret());
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
            return this.UpdateDeblindedPassword(deblindedPassword, updateToken);
        }

        public bool Verify(byte[] transformedPassword, byte[] blindedPassword, 
            byte[] salt, byte[] proofKey, byte[] proofC, byte[] proofU)
        {
            return this.pythia.Verify(transformedPassword, blindedPassword, 
                salt, proofKey, proofC, proofU);
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
