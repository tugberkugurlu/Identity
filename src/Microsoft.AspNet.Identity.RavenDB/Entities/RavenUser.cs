using System;
using Raven.Imports.Newtonsoft.Json;

namespace Microsoft.AspNet.Identity.RavenDB
{
    public class RavenUser
    {
        [JsonConstructor]
        public RavenUser(string userName)
        {
            if (userName == null) throw new ArgumentNullException("userName");
        }
    }
}