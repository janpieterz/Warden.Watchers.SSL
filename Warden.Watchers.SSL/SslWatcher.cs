using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Warden.Watchers.SSL
{
    public class SslWatcher : IWatcher
    {
        private readonly SslWatcherConfiguration _configuration;
        public string Group { get; }
        public string Name { get; }
        public const string DefaultName = "SSL Watcher";
        public async Task<IWatcherCheckResult> ExecuteAsync()
        {
            try
            {
                X509Certificate2 certificate2 = null;
#if NET461
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(_configuration.Uri);
                HttpWebResponse response = (HttpWebResponse)(await request.GetResponseAsync());
                response.Dispose();
                var certificate = request.ServicePoint.Certificate;
                if (certificate == null)
                {
                    return SslWatcherCheckResult.Create(this, false, _configuration.Uri, null,
                        $"{_configuration.Uri} does not appear to have a SSL certificate");
                }
                certificate2 = new X509Certificate2(certificate);

#else
                HttpClientHandler handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback =
                        delegate(HttpRequestMessage message, X509Certificate2 x509Certificate2, X509Chain arg3,
                            SslPolicyErrors arg4)
                        {
                            certificate2 = new X509Certificate2(x509Certificate2.RawData);
                            return true;
                        }
                };


                HttpClient client = new HttpClient(handler, true);
                await client.GetAsync(_configuration.Uri);
                
                if (certificate2 == null)
                {
                    throw new Exception("No certificate created.");
                }
#endif
                return await EnsureAsync(_configuration.Uri, certificate2);
            }
            catch (Exception exception)
            {
                throw new WatcherException($"There was an error while trying to access the SSL endpoint: `{_configuration.Uri}`", exception);
            }
        }

        private async Task<IWatcherCheckResult> EnsureAsync(Uri configurationUri, X509Certificate2 certificate2)
        {
            bool isValid = true;

            if (_configuration.ExpirationAfter != default(TimeSpan) && certificate2.NotAfter - DateTime.Now < _configuration.ExpirationAfter)
            {
                return SslWatcherCheckResult.Create(this, false, configurationUri, certificate2,
                    $"SSL endpoint `{configurationUri}` has returned a certificate that will expire too soon: {certificate2.NotAfter}.");
            }

            if (_configuration.EnsureThatAsync != null)
            {
                isValid = await _configuration.EnsureThatAsync?.Invoke(certificate2);
            }
            isValid = isValid && (_configuration.EnsureThat?.Invoke(certificate2) ?? true);

            return SslWatcherCheckResult.Create(this, isValid, configurationUri, certificate2,
                $"SSL endoint `{configurationUri}` has returned a certificate with thumbprint {certificate2.Thumbprint} which expires {certificate2.NotAfter}, signed by {certificate2.IssuerName.Name}");
        }
        protected SslWatcher(string name, SslWatcherConfiguration configuration, string group)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("Watcher name cannot be empty.");
            }
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration), "SSL Watcher configuration has not been provided.");
            }

            Name = name;
            _configuration = configuration;
            Group = group;
        }
        public static SslWatcher Create(string name, SslWatcherConfiguration configuration, string group = null) => new SslWatcher(name, configuration, group);

        public static SslWatcher Create(string url, Action<SslWatcherConfiguration.Default> configurator = null,
            string group = null) => Create(DefaultName, url, configurator, group);

        public static SslWatcher Create(string name, string url,
                Action<SslWatcherConfiguration.Default> configurator = null, string group = null)
        {
            var config = new SslWatcherConfiguration.Builder(url);
            configurator?.Invoke((SslWatcherConfiguration.Default) config);
            return Create(name, config.Build(), group);
        }

    }
}
