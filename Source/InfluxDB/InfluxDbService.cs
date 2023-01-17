using System;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace MQTTnet.Server.InfluxDB
{

    public sealed class InfluxDbService
    {
        private static readonly Lazy<InfluxDbService> lazy = new Lazy<InfluxDbService>(() => new InfluxDbService());
        private IConfigurationRoot config;

        public static InfluxDbService Instance
        {
            get
            {
                return lazy.Value;
            }
        }

        private InfluxDbService()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false);

            config = builder.Build();

            Connect();
        }

        private void Connect()
        {
            throw new NotImplementedException();
        }
    }
}