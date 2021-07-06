using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;

using Newtonsoft.Json;
using NLog;

using ZitiDesktopEdge.DataStructures;
using ZitiDesktopEdge.Server;

/// <summary>
/// The implementation will abstract away the setup of the communication to
/// the monitor service. This implementation will communicate to the service over a
/// a NamedPipe.
/// 
/// All communication is effectively serial - one or more messages sent and 
/// one or more messages returned.
/// 
/// </summary>
namespace ZitiDesktopEdge.ServiceClient {
    public class MonitorClient : AbstractClient {
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger();
        protected override Logger Logger { get { return _logger; } }

        public const int EXPECTED_API_VERSION = 1;

        public event EventHandler<MonitorServiceStatusEvent> OnServiceStatusEvent;
        public event EventHandler<InstallationNotificationEvent> OnNotificationEvent;

        protected virtual void ServiceStatusEvent(MonitorServiceStatusEvent e) {
            OnServiceStatusEvent?.Invoke(this, e);
        }

        protected virtual void InstallationNotificationEvent(InstallationNotificationEvent e) {
            OnNotificationEvent?.Invoke(this, e);
        }

        public MonitorClient() : base() {
        }

        async protected override Task ConnectPipesAsync() {
            await semaphoreSlim.WaitAsync();
            try {
                pipeClient = new NamedPipeClientStream(localPipeServer, IPCServer.PipeName, PipeDirection.InOut);
                eventClient = new NamedPipeClientStream(localPipeServer, IPCServer.EventPipeName, PipeDirection.In);
                await eventClient.ConnectAsync(ServiceConnectTimeout);
                await pipeClient.ConnectAsync(ServiceConnectTimeout);
                ClientConnected(null);
            } catch (Exception ex) {
                semaphoreSlim.Release();
                throw new ServiceException("Could not connect to the service.", 1, ex.Message);
            }
            semaphoreSlim.Release();
        }

        protected override void ProcessLine(string line) {
            var jsonReader = new JsonTextReader(new StringReader(line));
            MonitorServiceStatusEvent evt = serializer.Deserialize<MonitorServiceStatusEvent>(jsonReader);
            switch(evt.Type)
            {
                case "Notification":
                    jsonReader = new JsonTextReader(new StringReader(line));
                    InstallationNotificationEvent instEvt = serializer.Deserialize<InstallationNotificationEvent>(jsonReader);
                    InstallationNotificationEvent(instEvt);
                    break;
                default:
                    ServiceStatusEvent(evt);
                    break;
            }
        }

        async internal Task<string> SendServiceFunctionAsync(object toSend) {
            try {
                await sendAsync(toSend);
                var resp = await readMessageAsync(ipcReader);
                Logger.Info("RESPONSE: {0}", resp);
                return resp;
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }

        async public Task<MonitorServiceStatusEvent> StopServiceAsync() {
            ActionEvent action = new ActionEvent() { Op = "Stop", Action = "Normal" };
            try {
                await sendAsync(action);
                return await readAsync<MonitorServiceStatusEvent>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<MonitorServiceStatusEvent> StartServiceAsync() {
            ActionEvent action = new ActionEvent() { Op = "Start", Action = "Normal" };
            try {
                await sendAsync(action);
                return await readAsync<MonitorServiceStatusEvent>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<MonitorServiceStatusEvent> ForceTerminateAsync() {
            ActionEvent action = new ActionEvent() { Op = "Stop", Action = "Force" };
            try {
                await sendAsync(action);
                return await readAsync<MonitorServiceStatusEvent>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<MonitorServiceStatusEvent> StatusAsync() {
            ActionEvent action = new ActionEvent() { Op = "Status", Action = "" };
            try {
                await sendAsync(action);
                return await readAsync<MonitorServiceStatusEvent>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<MonitorServiceStatusEvent> CaptureLogsAsync() {
            ActionEvent action = new ActionEvent() { Op = "CaptureLogs", Action = "Normal" };
            try {
                await sendAsync(action);
                return await readAsync<MonitorServiceStatusEvent>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<SvcResponse> SetReleaseStreamAsync(string stream) {
            ActionEvent action = new ActionEvent() { Op = "SetReleaseStream", Action = stream };
            try {
                await sendAsync(action);
                return await readAsync<SvcResponse>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<SvcResponse> SetLogLevelAsync(string level) {
            if ("verbose".Equals(level?.ToLower())) {
                //only the data client understands verbose - so use trace...
                level = "TRACE";
            }
            ActionEvent action = new ActionEvent() { Op = "SetLogLevel", Action = level };
            try {
                await sendAsync(action);
                return await readAsync<SvcResponse>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<StatusCheck> DoUpdateCheck() {
            ActionEvent action = new ActionEvent() { Op = "DoUpdateCheck", Action = "" };
            try {
                await sendAsync(action);
                return await readAsync<StatusCheck>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
        async public Task<SvcResponse> TriggerUpdate() {
            ActionEvent action = new ActionEvent() { Op = "TriggerUpdate", Action = "" };
            try {
                await sendAsync(action);
                return await readAsync<SvcResponse>(ipcReader);
            } catch (Exception ex) {
                Logger.Error(ex, "Unexpected error");
            }
            return null;
        }
    }
}