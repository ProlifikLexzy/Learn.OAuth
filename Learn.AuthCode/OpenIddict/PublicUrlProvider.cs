using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Learn.AuthCode.OpenIddict;
internal interface IPublicUrlProvider
{
    /// <summary>
    /// Public URL to be able to use relative URLs in Client's RedirectUri
    /// </summary>
    string PublicUrl { get; set; }
}

internal class PublicUrlProvider : IPublicUrlProvider
{
    /// <inheritdoc cref="IPublicUrlProvider.PublicUrl"/>
    public string PublicUrl { get; set; }

    public PublicUrlProvider(string publicUrl)
    {
        PublicUrl = publicUrl;
    }
}
