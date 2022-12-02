using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace Learn.AuthCode.OpenIddict;
/// <summary>
/// Provides configuration for openiddict client (
/// </summary>
public class OpenIddictClientConfigurationProvider : IOpenIddictClientConfigurationProvider
{
    private readonly Dictionary<string, OpenIddictClientConfiguration> _clients;

    /// <summary>
    /// Constructs OpenIddictClientConfigurationProvider 
    /// </summary>
    public OpenIddictClientConfigurationProvider(IOptions<OpenIddictConfiguration> configuration)
    {
        _clients = configuration.Value.Clients.Values.ToDictionary(x => x.ClientId);
    }

    /// <inheritdoc />
    public OpenIddictClientConfiguration GetConfiguration(string clientId)
    {
        return _clients[clientId];
    }

    /// <inheritdoc />
    public bool TryGetConfiguration(
        string clientId,
        out OpenIddictClientConfiguration configuration
    )
    {
        return _clients.TryGetValue(clientId, out configuration);
    }

    /// <inheritdoc />
    public IList<OpenIddictClientConfiguration> GetAllConfigurations()
    {
        return _clients.Values.ToList();
    }
}
