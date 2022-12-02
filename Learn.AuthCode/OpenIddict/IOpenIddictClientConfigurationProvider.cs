using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Learn.AuthCode.OpenIddict;
/// <summary>
/// Provides configurations for OpenId clients
/// </summary>
public interface IOpenIddictClientConfigurationProvider
{
    /// <summary>
    /// Returns configuration for passed clientId or null if client is not found. 
    /// </summary>
    OpenIddictClientConfiguration? GetConfiguration(string clientId);

    /// <summary>
    /// Returns configuration for passed clientId (and `true` as returnor null if client is not found. 
    /// </summary>
    bool TryGetConfiguration(string clientId, out OpenIddictClientConfiguration configuration);

    /// <summary>
    /// Returns configuration for all clients
    /// </summary>
    IList<OpenIddictClientConfiguration> GetAllConfigurations();
}
