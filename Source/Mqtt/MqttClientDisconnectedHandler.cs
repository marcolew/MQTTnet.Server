using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using MQTTnet.Server.Scripting;

namespace MQTTnet.Server.Mqtt
{
    public class MqttClientDisconnectedHandler : IMqttServerClientDisconnectedHandler
    {
        private readonly ILogger _logger;

        public MqttClientDisconnectedHandler(ILogger<MqttClientDisconnectedHandler> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task HandleClientDisconnectedAsync(MqttServerClientDisconnectedEventArgs eventArgs)
        {
            try
            {
               
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Error while handling client disconnected event.");
            }

            return Task.CompletedTask;
        }
    }
}
