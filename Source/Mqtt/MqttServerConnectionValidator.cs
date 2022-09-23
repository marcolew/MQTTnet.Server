using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using MQTTnet.Protocol;
using MQTTnet.Server.Scripting;

namespace MQTTnet.Server.Mqtt
{
    public class MqttServerConnectionValidator : IMqttServerConnectionValidator
    {
        public const string WrappedSessionItemsKey = "WRAPPED_ITEMS";

        private readonly ILogger _logger;

        public MqttServerConnectionValidator(ILogger<MqttServerConnectionValidator> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public Task ValidateConnectionAsync(MqttConnectionValidatorContext context)
        {
            try
            {
                
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Error while validating client connection.");

                context.ReasonCode = MqttConnectReasonCode.UnspecifiedError;
            }

            return Task.CompletedTask;
        }
    }
}
