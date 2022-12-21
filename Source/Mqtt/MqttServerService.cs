using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using MQTTnet.Adapter;
using MQTTnet.AspNetCore;
using MQTTnet.Client;
using MQTTnet.Implementations;
using MQTTnet.Protocol;
using MQTTnet.Server.Configuration;
using MQTTnet.Server.Scripting;
using MQTTnet.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Net.Security;

namespace MQTTnet.Server.Mqtt
{
    public class MqttServerService
    {
        readonly ILogger<MqttServerService> _logger;

        readonly MqttSettingsModel _settings;
        private X509Certificate2 ca;
        readonly MqttServer _mqttServer;
        readonly MqttWebSocketServerAdapter _webSocketServerAdapter;
        private X509Certificate2 certificate;



        public MqttServerService(
            MqttSettingsModel mqttSettings,
            CustomMqttFactory mqttFactory,
            ILogger<MqttServerService> logger)
        {
            _settings = mqttSettings ?? throw new ArgumentNullException(nameof(mqttSettings));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            //_webSocketServerAdapter = new MqttWebSocketServerAdapter(mqttFactory.Logger);

            //var adapters = new List<IMqttServerAdapter>
            //{
            //    new MqttTcpServerAdapter(mqttFactory.Logger)
            //    {
            //        TreatSocketOpeningErrorAsWarning = true // Opening other ports than for HTTP is not allows in Azure App Services.
            //    },
            //    _webSocketServerAdapter
            //};
            var pfx = new FileInfo("server.pfx");
            certificate = new X509Certificate2(pfx.FullName, ".SWMS4lew", X509KeyStorageFlags.Exportable);

            var caFile = new FileInfo("ca.crt");
            ca = new X509Certificate2(caFile.FullName);

            _mqttServer = mqttFactory.CreateMqttServer(CreateMqttServerOptions());
        }

        public void Configure()
        {

            _mqttServer.ValidatingConnectionAsync += _mqttServer_ValidatingConnectionAsync;
            _mqttServer.ClientConnectedAsync += _mqttServer_ClientConnectedAsync; //+= _mqttClientConnectedHandler;
            _mqttServer.ClientDisconnectedAsync += _mqttServer_ClientDisconnectedAsync;  //= _mqttClientDisconnectedHandler;
            _mqttServer.ClientSubscribedTopicAsync += _mqttServer_ClientSubscribedTopicAsync; // = _mqttClientSubscribedTopicHandler;
            _mqttServer.ClientUnsubscribedTopicAsync += _mqttServer_ClientUnsubscribedTopicAsync; // = _mqttClientUnsubscribedTopicHandler;
            _mqttServer.InterceptingPublishAsync += _mqttServer_InterceptingPublishAsync;

            _mqttServer.StartAsync().GetAwaiter().GetResult();

            _logger.LogInformation("MQTT server started.");
        }

        private Task _mqttServer_ValidatingConnectionAsync(ValidatingConnectionEventArgs arg)
        {
                _logger.LogInformation($"Validating connection. {arg.ClientId} {arg.ClientCertificate.Subject} ");
                if (arg.ClientCertificate.Subject.ToLowerInvariant().Contains(arg.ClientId.ToLowerInvariant()) == false)
                {
                    return Task.FromException(new Exception("User not authorized"));
                }
            return Task.CompletedTask;
        }

        private Task _mqttServer_InterceptingPublishAsync(InterceptingPublishEventArgs arg)
        {
            return Task.Run(() =>
            {
                _logger.LogInformation($"Intercepting Publish {arg.ApplicationMessage.Topic}!");

            }
        );
        }

        private Task _mqttServer_ClientUnsubscribedTopicAsync(ClientUnsubscribedTopicEventArgs arg)
        {
            return Task.Run(() =>
            {
                _logger.LogInformation($"Client unsubscribed to topic {arg.TopicFilter}!");
            }
        );
        }

        private Task _mqttServer_ClientSubscribedTopicAsync(ClientSubscribedTopicEventArgs arg)
        {
            return Task.Run(() =>
            {
                _logger.LogInformation($"Client subscribed to topic {arg.TopicFilter}!");
            }
        );
        }

        private Task _mqttServer_ClientDisconnectedAsync(ClientDisconnectedEventArgs arg)
        {
            return Task.Run(() =>
            {
                _logger.LogInformation("Client disconnected!");
            }
        );
        }

        private Task _mqttServer_ClientConnectedAsync(ClientConnectedEventArgs arg)
        {
            return Task.Run(() =>
        {
            _logger.LogInformation($"Client connected! {arg.ClientId}");
            
        }
        );
        }

        public Task RunWebSocketConnectionAsync(WebSocket webSocket, HttpContext httpContext)
        {
            return _webSocketServerAdapter.RunWebSocketConnectionAsync(webSocket, httpContext);
        }

        public Task<IList<MqttClientStatus>> GetClientStatusAsync()
        {
            return _mqttServer.GetClientsAsync();
        }

        public Task<IList<MqttSessionStatus>> GetSessionStatusAsync()
        {
            return _mqttServer.GetSessionsAsync();
        }

        public Task ClearRetainedApplicationMessagesAsync()
        {
            return _mqttServer.DeleteRetainedMessagesAsync();
        }

        public Task<IList<MqttApplicationMessage>> GetRetainedApplicationMessagesAsync()
        {
            return _mqttServer.GetRetainedMessagesAsync();
        }

        public Task PublishAsync(MqttApplicationMessage applicationMessage)
        {
            if (applicationMessage == null) throw new ArgumentNullException(nameof(applicationMessage));

            return _mqttServer.InjectApplicationMessage(new InjectedMqttApplicationMessage(applicationMessage));
        }


        MqttServerOptions CreateMqttServerOptions()
        {
            var options = new MqttServerOptionsBuilder()
                .WithMaxPendingMessagesPerClient(_settings.MaxPendingMessagesPerClient)
                .WithDefaultCommunicationTimeout(TimeSpan.FromSeconds(_settings.CommunicationTimeout))
                                        .WithEncryptedEndpoint()
                        .WithEncryptedEndpointPort(2000)
                        .WithEncryptionCertificate(certificate.Export(X509ContentType.Pfx))
                        //.WithRemoteCertificateValidationCallback((obj, cert, chain, ssl) => { return true; })
                        .WithEncryptionSslProtocol(SslProtocols.Tls12);

            //.WithoutDefaultEndpoint();

            //.WithConnectionValidator(_mqttConnectionValidator)
            //.WithApplicationMessageInterceptor(_mqttApplicationMessageInterceptor)
            //.WithSubscriptionInterceptor(_mqttSubscriptionInterceptor)
            //.WithUnsubscriptionInterceptor(_mqttUnsubscriptionInterceptor)
            //.WithStorage(_mqttServerStorage);

            // Configure unencrypted connections
            //if (_settings.TcpEndPoint.Enabled)
            //{
            ///    options.WithDefaultEndpoint();

            //    if (_settings.TcpEndPoint.TryReadIPv4(out var address4))
            //  {
            //       options.WithDefaultEndpointBoundIPAddress(address4);
            //   }

            //   if (_settings.TcpEndPoint.TryReadIPv6(out var address6))
            //   {
            //       options.WithDefaultEndpointBoundIPV6Address(address6);
            //    }

            //     if (_settings.TcpEndPoint.Port > 0)
            //   {
            //        options.WithDefaultEndpointPort(_settings.TcpEndPoint.Port);
            //    }
            // }
            // else
            //{
            //     options.WithoutDefaultEndpoint();
            // }

            // Configure encrypted connections
            //if (_settings.EncryptedTcpEndPoint.Enabled)
            // {
            //#if NETCOREAPP3_1 || NET5_0
            //              options
            //                .WithEncryptedEndpoint()
            //              .WithEncryptionSslProtocol(SslProtocols.Tls13);/
            //#else
            //              options
            //                .WithEncryptedEndpoint()
            //              .WithEncryptionSslProtocol(SslProtocols.Tls12);
            //#endif

            //              if (!string.IsNullOrEmpty(_settings.EncryptedTcpEndPoint?.Certificate?.Path))
            //            {
            //              IMqttServerCertificateCredentials certificateCredentials = null;

            //             if (!string.IsNullOrEmpty(_settings.EncryptedTcpEndPoint?.Certificate?.Password))
            //         {
            //               certificateCredentials = new MqttServerCertificateCredentials
            //               {
            //                  Password = _settings.EncryptedTcpEndPoint.Certificate.Password
            //              };
            //          }

            //          options.WithEncryptionCertificate(_settings.EncryptedTcpEndPoint.Certificate.ReadCertificate(), certificateCredentials);
            //      }

            //     if (_settings.EncryptedTcpEndPoint.TryReadIPv4(out var address4))
            //     {
            //         options.WithEncryptedEndpointBoundIPAddress(address4);
            //     }

            //       if (_settings.EncryptedTcpEndPoint.TryReadIPv6(out var address6))
            //     {
            //          options.WithEncryptedEndpointBoundIPV6Address(address6);
            //      }

            //      if (_settings.EncryptedTcpEndPoint.Port > 0)
            //      {
            //           options.WithEncryptedEndpointPort(_settings.EncryptedTcpEndPoint.Port);
            //      }
            //   }
            //   else
            //   {
            //       options.WithoutEncryptedEndpoint();
            //   }

            //    if (_settings.ConnectionBacklog > 0)
            //    {
            //      options.WithConnectionBacklog(_settings.ConnectionBacklog);
            //  }

            //  if (_settings.EnablePersistentSessions)
            // {
            //   options.WithPersistentSessions();
            //  }

            var opt = options.Build();

            opt.DefaultEndpointOptions.IsEnabled = false;
            opt.TlsEndpointOptions.ClientCertificateRequired = true;

            opt.TlsEndpointOptions.RemoteCertificateValidationCallback += (sender, cer, chain, sslPolicyErrors) =>
            {
                try
                {
                    if (cer != null)
                    {
                        string hostName = ((X509Certificate)cer).GetIssuerName();
                    }

                    if (sslPolicyErrors == SslPolicyErrors.None)
                    {
                        return true;
                    }

                    if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                        chain.ChainPolicy.ExtraStore.Add(ca);

                        chain.Build((X509Certificate2)cer);

                        return chain.ChainElements.Cast<X509ChainElement>().Any(a => a.Certificate.Thumbprint == ca.Thumbprint);
                    }
                }
                catch { }

                return false;
            };

            return opt;
        }
    }
}