using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Learn.AuthCode.OpenIddict;
/// <summary>
/// DTO for certificate information
/// </summary>
public class OpenIdCertificateInfo
{
    /// <summary>
    /// Certificate in base64 format (so that it could be injected via env. variables)
    /// </summary>
    public string Base64Certificate { get; set; }

    /// <summary>
    /// Certificate password
    /// </summary>
    public string Password { get; set; }
}