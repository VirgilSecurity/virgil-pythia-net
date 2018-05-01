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
    using System.Collections.Generic;

    /// <summary>
    /// The <see cref="PythiaProtocolConfig"/> class contains a list of 
    /// configuration parameters that required for <see cref="PythiaProtocol"/>
    /// class initialization.
    /// </summary>
    /// <remarks>
    /// To use the Pythia Protocol, you must register your app project on the 
    /// Virgil Developer https://developer.virgilsecurity.com/ and get an 
    /// application credentials.
    /// </remarks>
    public class PythiaProtocolConfig
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PythiaProtocolConfig"/> class.
        /// </summary>
        public PythiaProtocolConfig()
        {
            this.ApiBaseURL = "https://api.virgilsecurity.com";
        }
        
        /// <summary>
        /// Gets or sets the <c>AppId</c> that represents your Pythia application 
        /// in Virgil Cloud Services.
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// Gets or Sets the <c>ApiKeyId</c> that identifies a Public Key that is
        /// related to the <see cref="ApiKey"/> used to verify JWT tokens come
        /// to the Pythia Service.
        /// </summary>
        public string ApiKeyId { get; set; }

        /// <summary>
        /// Gets or Sets the ApiKey that is used to generate a JWT token 
        /// and authenticate Pythia Serivce requests.
        /// </summary>
        public string ApiKey { get; set; }

        /// <summary>
        /// Gets or sets the list of Proof Keys. Grub this parameter from your
        /// Pythia application on the Virgil Dashboard.
        /// </summary>
        public IEnumerable<string> ProofKeys { get; set; }

        /// <summary>
        /// Gets or sets the API base URL. By default it sets 
        /// to the https://api.virgilsecurity.com
        /// </summary>
        public string ApiURL { get; set; }
    }
}
