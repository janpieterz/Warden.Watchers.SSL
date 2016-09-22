using System;
using Warden.Core;

namespace Warden.Watchers.SSL
{
    public static class Extensions
    {
        public static WardenConfiguration.Builder AddSslWatcher(this WardenConfiguration.Builder builder, string url,
            Action<WatcherHooksConfiguration.Builder> hooks = null, TimeSpan? interval = null, string group = null)
        {
            builder.AddWatcher(SslWatcher.Create(url, group: group), hooks, interval);
            return builder;
        }

        public static WardenConfiguration.Builder AddSslWatcher(this WardenConfiguration.Builder builder, string name,
            string url, Action<WatcherHooksConfiguration.Builder> hooks = null, TimeSpan? interval = null,
            string group = null)
        {
            builder.AddWatcher(SslWatcher.Create(name, url, group: group), hooks, interval);
            return builder;
        }

        public static WardenConfiguration.Builder AddSslWatcher(this WardenConfiguration.Builder builder, string url, Action<SslWatcherConfiguration.Default> configurator, Action<WatcherHooksConfiguration.Builder> hooks = null, TimeSpan? interval = null,
            string group = null)
        {
            builder.AddWatcher(SslWatcher.Create(url, configurator, group: group), hooks, interval);
            return builder;
        }

        public static WardenConfiguration.Builder AddSslWatcher(this WardenConfiguration.Builder builder, string name, string url, Action<SslWatcherConfiguration.Default> configurator, Action<WatcherHooksConfiguration.Builder> hooks = null, TimeSpan? interval = null,
            string group = null)
        {
            builder.AddWatcher(SslWatcher.Create(name, url, configurator, group: group), hooks, interval);
            return builder;
        }
    }
}
