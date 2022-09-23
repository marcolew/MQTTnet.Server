using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using MQTTnet.Server.Scripting;

namespace MQTTnet.Server.Mqtt
{
    public class MqttUnsubscriptionInterceptor : IMqttServerUnsubscriptionInterceptor
    {
        private readonly ILogger _logger;

        public MqttUnsubscriptionInterceptor(ILogger<MqttUnsubscriptionInterceptor> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task InterceptUnsubscriptionAsync(MqttUnsubscriptionInterceptorContext context)
        {
            try
            {
              
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Error while intercepting unsubscription.");
            }

            return Task.CompletedTask;
        }
    }
}
