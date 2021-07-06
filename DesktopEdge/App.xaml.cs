using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.IO.Pipes;
using System.IO;
using System.Threading.Tasks;

using System.Windows.Interop;

using NLog;
using Windows.ApplicationModel.Activation;
using Microsoft.Toolkit.Uwp.Notifications;
using ZitiDesktopEdge.ServiceClient;

namespace ZitiDesktopEdge {
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application {
        private const string NamedPipeName = "ZitiDesktopEdgePipe";

        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private static Mutex _mutex = null;

		protected override void OnSessionEnding(SessionEndingCancelEventArgs e) {
			base.OnSessionEnding(e);
		}

		protected override void OnStartup(StartupEventArgs e) {
            const string appName = "Ziti Desktop Edge";

            bool createdNew;

            _mutex = new Mutex(true, appName, out createdNew);

            if (!createdNew) {
                using (var client = new NamedPipeClientStream(NamedPipeName)) {
                    logger.Info("Another instance exists. Attempting to notify it to open");
                    try {
                        client.Connect(1000);
                    } catch {
                        return;
                    }

                    if (!client.IsConnected)
                        return;

                    using (StreamWriter writer = new StreamWriter(client)) {
                        writer.Write("showscreen");
                        writer.Flush();
                    }
                }
                Application.Current.Shutdown();
            } else {
#pragma warning disable 4014 //This async method lacks 'await'
                StartServer();
#pragma warning restore 4014 //This async method lacks 'await'
            }
        }

        async public Task StartServer() {
            logger.Debug("Starting IPC server to listen for other instances of the app");
            while (true) {
                string text;
                using (var server = new NamedPipeServerStream(NamedPipeName)) {
                    await server.WaitForConnectionAsync();
                    logger.Debug("Another instance opened and connected.");
                    using (StreamReader reader = new StreamReader(server)) {
                        text = await reader.ReadToEndAsync();
                    }
                }

                logger.Debug("received: {0}. Calling OnReceivedString", text);
                OnReceivedString(text);
            }
        }

        public event Action<string> ReceiveString;
        protected virtual void OnReceivedString(string text) => ReceiveString?.Invoke(text);

    }
}