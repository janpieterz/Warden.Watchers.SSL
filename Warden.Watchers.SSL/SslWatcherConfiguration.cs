using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Warden.Watchers.SSL
{
    public class SslWatcherConfiguration
    {
        public Uri Uri { get; protected set; }
        public Func<X509Certificate2, Task<bool>> EnsureThatAsync { get; protected set; }
        public Func<X509Certificate2, bool> EnsureThat { get; protected set; }

        protected internal SslWatcherConfiguration(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                throw new ArgumentException("URL can not be empty.", nameof(url));
            }
            Uri = new Uri(url);
        }

        public class Default : Configurator<Default>
        {
            public Default(SslWatcherConfiguration configuration) : base(configuration)
            {
                SetInstance(this);
            }
        }

        public class Configurator<T> : WatcherConfigurator<T, SslWatcherConfiguration> where T : Configurator<T>
        {
            protected Configurator(string url)
            {
                Configuration = new SslWatcherConfiguration(url);
            }

            protected Configurator(SslWatcherConfiguration configuration) : base(configuration)
            {
            }

            public T EnsureThat(Func<X509Certificate2, bool> ensureThat)
            {
                if (ensureThat == null)
                {
                    throw new ArgumentException("Ensure that predicate can not be null", nameof(ensureThat));
                }
                Configuration.EnsureThat = ensureThat;
                return Configurator;
            }

            public T EnsureThatAsync(Func<X509Certificate2, Task<bool>> ensureThat)
            {
                if (ensureThat == null)
                    throw new ArgumentException("Ensure that async predicate can not be null.", nameof(ensureThat));

                Configuration.EnsureThatAsync = ensureThat;

                return Configurator;
            }
        }

        public class Builder : Configurator<Builder>
        {
            public Builder(string url) : base(url)
            {
                SetInstance(this);
            }

            public SslWatcherConfiguration Build() => Configuration;

            public static explicit operator Default(Builder builder) => new Default(builder.Configuration);
        }
    }
}