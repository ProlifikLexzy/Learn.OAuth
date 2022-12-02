using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Learn.AuthCode.OpenIddict;
/// <summary>
/// OpenIddict configuration
/// </summary>
public class OpenIddictConfiguration
{
    /// <summary>
    /// OpenId clients to be registered in openiddict
    /// </summary>
    public Dictionary<string, OpenIddictClientConfiguration> Clients { get; set; }
    /// <summary>
    /// </summary>
    public OpenIdCertificateInfo SigningCertificate { get; set; }
    public OpenIdCertificateInfo EncryptionCertificate { get; set; }

    /// <summary>
    /// Public URL to be able to use relative URLs in Client's RedirectUri
    /// </summary>
    public string PublicUrl { get; set; }
}
