namespace Virgil.Pythia.Tests
{
    using System.Configuration;
    using System.Collections.Generic;
    using System.Runtime.Serialization;
    using Newtonsoft.Json;
    using System;

    [DataContract]
    public class AppSettings
    {
        static AppSettings()
        {
            var appSettingsJSON = ResourceHelper.GetEmbeddedResource(@"appsettings.json");
            Get = JsonConvert.DeserializeObject<AppSettings>(appSettingsJSON);
        }

        public static AppSettings Get { get; private set; }

        [DataMember(Name = "app_url")]
        public string ApiURL { get; set; }

        [DataMember(Name = "app_id")]
        public string AppId { get; set; }

        [DataMember(Name = "api_key_id")]
        public string ApiKeyId { get; set; }

        [DataMember(Name = "api_key")]
        public string ApiKey { get; set; }

        [DataMember(Name = "update_token")]
        public string UpdateToken { get; set; }

        [DataMember(Name = "proof_keys")]
        public List<string> ProofKeys { get; set; }

        [DataMember(Name = "pythia_protocol_testdata")]
        public PythiaProtocolTestDataModel ProtocolTestData { get; set; }

        [DataContract]
        public class PythiaProtocolTestDataModel
        {
            [DataMember(Name = "kProofKeys")]
            public List<string> ProofKeys { get; set; }

            [DataMember(Name = "kInvalidProofKey")]
            public string InvalidProofKey { get; set; }

            [DataMember(Name = "kInvalidUpdateToken")]
            public string InvalidUpdateToken { get; set; }
        }
    }
}
