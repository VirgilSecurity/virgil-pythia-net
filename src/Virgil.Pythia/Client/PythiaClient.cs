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

namespace Virgil.Pythia.Client
{
    using System;
    using System.Threading.Tasks;

    using Virgil.SDK.Common;
    using Virgil.SDK.Web.Connection;

    /// <summary>
    /// The <see cref="PythiaClient"/> class provides a list of methods 
    /// that executes the Pythia Service endpoints.
    /// </summary>
    public class PythiaClient : IPythiaClient
    {
        private readonly IConnection connection;
        private readonly IJsonSerializer serializer;

        /// <summary>
        /// Initializes a new instance of the <see cref="PythiaClient"/> class.
        /// </summary>
        /// <param name="connection">Connection.</param>
        public PythiaClient(IConnection connection, IJsonSerializer serializer)
        {
            this.connection = connection;
            this.serializer = serializer;
        }
        
        /// <summary>
        /// Performs blinded password transformation by calling <c>transform</c> 
        /// operation on the Pythia Serivce.
        /// </summary>
        public async Task<TransformResultModel> TransformPasswordAsync(TransformModel model, string accessToken)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            var request = HttpRequest.Create(HttpRequestMethod.Post)
                .WithAuthorization(accessToken)
                .WithBody(this.serializer, model)
                .WithEndpoint("/pythia/v1/password");

            var response = await this.connection.SendAsync(request)
                .ConfigureAwait(false);
            
            var result = response
                .HandleError(this.serializer)
                .Parse<TransformResultModel>(this.serializer);

            return result;
        }

        /// <summary>
        /// Performs generating seed operation by calling <c>transform</c> 
        /// operation on the Pythia Serivce.
        /// </summary>
        public async Task<GenerateSeedResultModel> GenerateSeedAsync(GenerateSeedModel model, string accessToken)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            var request = HttpRequest.Create(HttpRequestMethod.Post)
                .WithAuthorization(accessToken)
                .WithBody(this.serializer, model)
                .WithEndpoint("/pythia/v1/brainkey");

            var response = await this.connection.SendAsync(request)
                .ConfigureAwait(false);

            var result = response
                .HandleError(this.serializer)
                .Parse<GenerateSeedResultModel>(this.serializer);

            return result;
        }
    }
}
