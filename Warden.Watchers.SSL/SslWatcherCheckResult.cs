using System;
using System.Security.Cryptography.X509Certificates;

namespace Warden.Watchers.SSL
{
    public class SslWatcherCheckResult : WatcherCheckResult
    {
        public Uri Uri { get; }
        public X509Certificate2 Certificate { get; }

        public SslWatcherCheckResult(SslWatcher watcher, bool isValid, string description, Uri uri, X509Certificate2 certificate) : base(watcher, isValid, description)
        {
            Uri = uri;
            Certificate = certificate;
        }

        public static SslWatcherCheckResult Create(SslWatcher watcher, bool isValid, Uri uri,
                X509Certificate2 certificate, string description = "")
            => new SslWatcherCheckResult(watcher, isValid, description, uri, certificate);
    }
}