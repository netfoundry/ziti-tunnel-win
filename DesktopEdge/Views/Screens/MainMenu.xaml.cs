using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Diagnostics;
using System;
using System.Reflection;
using System.Net.Mail;
using System.IO;
using NLog;

using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.DataStructures;
using ZitiDesktopEdge.ServiceClient;
using System.Configuration;

namespace ZitiDesktopEdge {
	/// <summary>
	/// Interaction logic for MainMenu.xaml
	/// </summary>
	public partial class MainMenu : UserControl {
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public delegate void AttachementChanged(bool attached);
		public event AttachementChanged OnAttachmentChange;
		public delegate void LogLevelChanged(string level);
		public event LogLevelChanged OnLogLevelChanged;
		public delegate void Detched(MouseButtonEventArgs e);
		public event Detched OnDetach;
		public string menuState = "Main";
		public string licenseData = "it's open source.";
		public string LogLevel = "";
		private string appVersion = null;
		private bool allowReleaseSelect = false;
		public double MainHeight = 500;

		private bool isBeta {
			get {
				return Application.Current.Properties["ReleaseStream"]?.ToString() == "beta";
			}
		}

		internal MainWindow MainWindow { get; set; }

		public MainMenu() {
			InitializeComponent();
			Application.Current.MainWindow.Title = "Ziti Desktop Edge";

			try {
				allowReleaseSelect = bool.Parse(ConfigurationManager.AppSettings.Get("ReleaseStreamSelect"));
			} catch {
				//if we can't parse the config - leave it as false...
				allowReleaseSelect = false; //setting it here in case anyone changes the default above
			}
#if DEBUG
			Debug.WriteLine("OVERRIDING allowReleaseSelect to true!");
			allowReleaseSelect = true;
#endif
			appVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
			LicensesItems.Text = licenseData;
			// don't check from the UI any more... CheckUpdates();
		}

		private void HideMenu(object sender, MouseButtonEventArgs e) {
			menuState = "Menu";
			UpdateState();
			MainMenuArea.Visibility = Visibility.Collapsed;
		}
		private void Window_MouseDown(object sender, MouseButtonEventArgs e) {
			if (e.ChangedButton == MouseButton.Left) {
				OnDetach(e);
			}
		}

		private void CloseApp(object sender, MouseButtonEventArgs e) {
			Application.Current.Shutdown();
		}

		private void ShowAbout(object sender, MouseButtonEventArgs e) {
			menuState = "About";
			UpdateState();
		}

		private void ShowAdvanced(object sender, MouseButtonEventArgs e) {
			menuState = "Advanced";
			UpdateState();
		}
		private void ShowIdentities(object sender, MouseButtonEventArgs e) {
			menuState = "Identities";
			UpdateState();
		}
		private void ShowLicenses(object sender, MouseButtonEventArgs e) {
			menuState = "Licenses";
			UpdateState();
		}
		private void ShowConfig(object sender, MouseButtonEventArgs e) {
			menuState = "Config";
			UpdateState();
		}
		private void ShowLogs(object sender, MouseButtonEventArgs e) {
			menuState = "Logs";
			UpdateState();
		}
		private void ShowUILogs(object sender, MouseButtonEventArgs e) {
			menuState = "UILogs";
			UpdateState();
		}
		private void ShowReleaseStreamMenuAction(object sender, MouseButtonEventArgs e) {
			logger.Warn("this is ShowReleaseStreamMenuAction at warn");
			logger.Info("this is ShowReleaseStreamMenuAction at info");
			logger.Debug("this is ShowReleaseStreamMenuAction at debug");
			logger.Trace("this is ShowReleaseStreamMenuAction at trace");
			menuState = "SetReleaseStream";
			UpdateState();
		}

		async private void SetReleaseStreamMenuAction(object sender, MouseButtonEventArgs e) {
			CheckForUpdateStatus.Visibility = Visibility.Collapsed;
			TriggerUpdateButton.Visibility = Visibility.Collapsed;
			SubOptionItem opt = (SubOptionItem)sender;
			var monitorClient = (MonitorClient)Application.Current.Properties["MonitorClient"];
			menuState = "SetReleaseStream";

			bool releaseClicked = opt.Label.ToLower() == "stable";

			if (releaseClicked) {
				if (isBeta) {
					//toggle to stable
					var r = await monitorClient.SetReleaseStreamAsync("stable");
					checkResponse(r, "Error When Setting Release Stream", "An error occurred while trying to set the release stream.");
				} else {
					logger.Debug("stable clicked but already on stable stream");
				}
			} else {
				if (!isBeta) {
					//toggle to beta
					var r = await monitorClient.SetReleaseStreamAsync("beta");
					checkResponse(r, "Error When Setting Release Stream", "An error occurred while trying to set the release stream.");
				} else {
					logger.Debug("beta clicked but already on beta stream");
				}
			}
			Application.Current.Properties["ReleaseStream"] = opt.Label.ToLower();
			UpdateState();
		}

		private void checkResponse(SvcResponse r, string titleOnErr, string msgOnErr) {
			if (r == null) {
				MainWindow.ShowError(titleOnErr, msgOnErr);
			} else {
				logger.Info(r?.ToString());
			}
		}

		private void SetLogLevel(object sender, MouseButtonEventArgs e) {
			menuState = "LogLevel";
			UpdateState();
		}

		private void UpdateState() {
			IdListScrollView.Height = this.ActualHeight-100.00;
			IdListScrollView.Visibility = Visibility.Collapsed;
			MainItems.Visibility = Visibility.Collapsed;
			AboutItems.Visibility = Visibility.Collapsed;
			MainItemsButton.Visibility = Visibility.Collapsed;
			AboutItemsArea.Visibility = Visibility.Collapsed;
			BackArrow.Visibility = Visibility.Collapsed;
			AdvancedItems.Visibility = Visibility.Collapsed;
			LicensesItems.Visibility = Visibility.Collapsed;
			LogsItems.Visibility = Visibility.Collapsed;
			ConfigItems.Visibility = Visibility.Collapsed;
			LogLevelItems.Visibility = Visibility.Collapsed;
			ReleaseStreamItems.Visibility = Visibility.Collapsed;

			if (menuState == "About") {
				MenuTitle.Content = "About";
				AboutItemsArea.Visibility = Visibility.Visible;
				AboutItems.Visibility = Visibility.Visible;
				BackArrow.Visibility = Visibility.Visible;

				string version = "";
				try {
					TunnelStatus s = (TunnelStatus)Application.Current.Properties["CurrentTunnelStatus"];
					version = $"{s.ServiceVersion.Version}@{s.ServiceVersion.Revision}";
				} catch (Exception e) {
					logger.Warn(e, "Could not get service version/revision?");
				}

				// Interface Version
				VersionInfo.Content = $"App: {appVersion} Service: {version}";

			} else if (menuState == "Advanced") {
				MenuTitle.Content = "Advanced Settings";
				AdvancedItems.Visibility = Visibility.Visible;
				BackArrow.Visibility = Visibility.Visible;
				ShowReleaseStreamMenuItem.Visibility = allowReleaseSelect ? Visibility.Visible : Visibility.Collapsed;
			} else if (menuState == "Licenses") {
				MenuTitle.Content = "Third Party Licenses";
				LicensesItems.Visibility = Visibility.Visible;
				BackArrow.Visibility = Visibility.Visible;
			} else if (menuState == "Logs") {
				MenuTitle.Content = "Advanced Settings";
				AdvancedItems.Visibility = Visibility.Visible;
				//string targetFile = NativeMethods.GetFinalPathName(MainWindow.ExpectedLogPathServices);
				string targetFile = MainWindow.ExpectedLogPathServices;

				OpenLogFile("service", targetFile);
				BackArrow.Visibility = Visibility.Visible;
			} else if (menuState == "UILogs") {
				MenuTitle.Content = "Advanced Settings";
				AdvancedItems.Visibility = Visibility.Visible;
				OpenLogFile("UI", MainWindow.ExpectedLogPathUI);
				BackArrow.Visibility = Visibility.Visible;
			} else if (menuState == "LogLevel") {
				ResetLevels();

				MenuTitle.Content = "Set Log Level";
				LogLevelItems.Visibility = Visibility.Visible;
				BackArrow.Visibility = Visibility.Visible;
			} else if (menuState == "SetReleaseStream") {
				SetReleaseStream();

				MenuTitle.Content = "Set Release Stream";
				ReleaseStreamItems.Visibility = allowReleaseSelect ? Visibility.Visible : Visibility.Collapsed;
				BackArrow.Visibility = Visibility.Visible;
			} else if (menuState == "Config") {
				MenuTitle.Content = "Tunnel Configuration";
				ConfigItems.Visibility = Visibility.Visible;
				BackArrow.Visibility = Visibility.Visible;

				ConfigIp.Value = Application.Current.Properties["ip"]?.ToString();
				ConfigSubnet.Value = Application.Current.Properties["subnet"]?.ToString();
				ConfigMtu.Value = Application.Current.Properties["mtu"]?.ToString();
				ConfigDns.Value = Application.Current.Properties["dns"]?.ToString();
			} else if (menuState == "Identities") {
				MenuTitle.Content = "Identities";
				IdListScrollView.Visibility = Visibility.Visible;
				BackArrow.Visibility = Visibility.Visible;
			} else {
				MenuTitle.Content = "Main Menu";
				MainItems.Visibility = Visibility.Visible;
				MainItemsButton.Visibility = Visibility.Visible;
				ReleaseStreamItems.Visibility = Visibility.Collapsed;
			}
		}

		private void OpenLogFile(string which, string logFile) {
			var whichRoot = Path.Combine(MainWindow.ExpectedLogPathRoot, which);
			try {
				string target = Native.NativeMethods.GetFinalPathName(logFile);
				if (File.Exists(target)) {
					logger.Info("opening {0} logs at: {1}", which, target);
					var p = Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
					if (p != null) {
						logger.Info("showing {0} logs. file: {1}", which, target);
					} else {
						Process.Start(whichRoot);
					}
					return;
				} else {
					logger.Warn("could not show {0} logs. file not found: {1}", which, target);
				}
			} catch {
			}
			Process.Start(whichRoot);
		}

		private void GoBack(object sender, MouseButtonEventArgs e) {
			if (menuState == "Config" || menuState == "LogLevel" || menuState == "UILogs" || menuState == "SetReleaseStream") {
				menuState = "Advanced";
			} else if (menuState == "Licenses") {
				menuState = "About";
			} else {
				menuState = "Menu";
			}
			UpdateState();
		}
		private void ShowPrivacy(object sender, MouseButtonEventArgs e) {
			Process.Start(new ProcessStartInfo("https://netfoundry.io/privacy") { UseShellExecute = true });
		}
		private void ShowTerms(object sender, MouseButtonEventArgs e) {
			Process.Start(new ProcessStartInfo("https://netfoundry.io/terms") { UseShellExecute = true });
		}

		async private void ShowFeedback(object sender, MouseButtonEventArgs e) {
			try {
				MainWindow.ShowLoad("Collecting Information", "Please wait while we run some commands\nand collect some diagnostic information");
				var mailMessage = new MailMessage("help@openziti.org", "help@openziti.org");
				mailMessage.Subject = "Ziti Support";
				mailMessage.IsBodyHtml = false;
				System.Text.StringBuilder sb = new System.Text.StringBuilder();
				sb.Append("Logs collected at : " + DateTime.Now.ToString());
				sb.Append(". client version : " + appVersion);

				mailMessage.Body = sb.ToString();

				string timestamp = DateTime.Now.ToFileTime().ToString();

				var dataClient = (DataClient)Application.Current.Properties["ServiceClient"];
				await dataClient.zitiDump();

				var monitorClient = (MonitorClient)Application.Current.Properties["MonitorClient"];
				MonitorServiceStatusEvent resp = await monitorClient.CaptureLogsAsync();
				if (resp == null) {
					logger.Error("no response from monitorClient?");
					MainWindow mw = (MainWindow)Application.Current.MainWindow;
					mw?.ShowError("Error Collecting Feedback", "An error occurred while trying to gather feedback.\nIs the monitor service running?");
					return;
				}
				string pathToLogs = resp.Message;
				logger.Info("Log files found at : {0}", resp.Message);
				mailMessage.Attachments.Add(new Attachment(pathToLogs));

				string emlFile = Path.Combine(Path.GetTempPath(), timestamp + "-ziti.eml");

				using (var filestream = File.Open(emlFile, FileMode.Create)) {
					var binaryWriter = new BinaryWriter(filestream);
					binaryWriter.Write(System.Text.Encoding.UTF8.GetBytes("X-Unsent: 1" + Environment.NewLine));
					var assembly = typeof(SmtpClient).Assembly;
					var mailWriterType = assembly.GetType("System.Net.Mail.MailWriter");
					var mailWriterContructor = mailWriterType.GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(Stream) }, null);
					var mailWriter = mailWriterContructor.Invoke(new object[] { filestream });
					var sendMethod = typeof(MailMessage).GetMethod("Send", BindingFlags.Instance | BindingFlags.NonPublic);
					sendMethod.Invoke(mailMessage, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { mailWriter, true, true }, null);
					var closeMethod = mailWriter.GetType().GetMethod("Close", BindingFlags.Instance | BindingFlags.NonPublic);
					closeMethod.Invoke(mailWriter, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { }, null);
				}
				var p = Process.Start(emlFile);
				if (p != null) {
					p.Exited += (object lambdaSender, EventArgs lambdaEventArgs) => {
						logger.Info("Removing temp file: {0}", emlFile);
						File.Delete(emlFile);
					};
					p.EnableRaisingEvents = true;
				} else {
					logger.Debug("process was null. most likely the email file format was not known when the process tried to start");
				}
			} catch (Exception ex) {
				logger.Warn(ex, "An unexpected error has occurred when submitting feedback? {0}", ex.Message);
			}
			MainWindow.HideLoad();
		}

		private void ShowSupport(object sender, MouseButtonEventArgs e) {
			Process.Start(new ProcessStartInfo("https://openziti.discourse.group/") { UseShellExecute = true });
		}

		private void DetachWindow(object sender, MouseButtonEventArgs e) {
			Application.Current.MainWindow.ShowInTaskbar = true;
			DetachButton.Visibility = Visibility.Collapsed;
			AttachButton.Visibility = Visibility.Visible;
			Arrow.Visibility = Visibility.Collapsed;
			if (OnAttachmentChange != null) {
				OnAttachmentChange(false);
			}
			MainMenuArea.Visibility = Visibility.Collapsed;
		}

		public void Detach() {
			Application.Current.MainWindow.ShowInTaskbar = true;
			DetachButton.Visibility = Visibility.Collapsed;
			AttachButton.Visibility = Visibility.Visible;
			Arrow.Visibility = Visibility.Collapsed;
		}
		private void RetachWindow(object sender, MouseButtonEventArgs e) {
			Application.Current.MainWindow.ShowInTaskbar = false;
			DetachButton.Visibility = Visibility.Visible;
			AttachButton.Visibility = Visibility.Collapsed;
			Arrow.Visibility = Visibility.Visible;
			if (OnAttachmentChange != null) {
				OnAttachmentChange(true);
			}
		}

		private void ResetLevels() {
			if (this.LogLevel == "") this.LogLevel = "error";
			LogVerbose.IsSelected = false;
			LogDebug.IsSelected = false;
			LogInfo.IsSelected = false;
			LogError.IsSelected = false;
			LogFatal.IsSelected = false;
			LogWarn.IsSelected = false;
			LogTrace.IsSelected = false;
			if (this.LogLevel == "verbose") LogVerbose.IsSelected = true;
			else if (this.LogLevel == "debug") LogDebug.IsSelected = true;
			else if (this.LogLevel == "info") LogInfo.IsSelected = true;
			else if (this.LogLevel == "error") LogError.IsSelected = true;
			else if (this.LogLevel == "fatal") LogFatal.IsSelected = true;
			else if (this.LogLevel == "warn") LogWarn.IsSelected = true;
			else if (this.LogLevel == "trace") LogTrace.IsSelected = true;
		}

		private void SetLevel(object sender, MouseButtonEventArgs e) {
			SubOptionItem item = (SubOptionItem)sender;
			this.LogLevel = item.Label.ToLower();
			if (OnLogLevelChanged != null) {
				OnLogLevelChanged(this.LogLevel);
			}
			ResetLevels();
		}

		private void SetReleaseStream() {
			this.ReleaseStreamItemBeta.IsSelected = isBeta;
			this.ReleaseStreamItemStable.IsSelected = !isBeta;
		}

		async private void CheckForUpdate_Click(object sender, RoutedEventArgs e) {
			logger.Info("checking for update...");
			try {
				CheckForUpdate.IsEnabled = false;
				CheckForUpdateStatus.Content = "Checking for update...";
				CheckForUpdateStatus.Visibility = Visibility.Visible;
				var monitorClient = (MonitorClient)Application.Current.Properties["MonitorClient"];
				var r = await monitorClient.DoUpdateCheck();
				checkResponse(r, "Error When Checking for Update", "An error occurred while trying check for update.");
				CheckForUpdateStatus.Content = r.Message;
				if (r.UpdateAvailable) {
					TriggerUpdateButton.Visibility = Visibility.Visible;
				} else {
					TriggerUpdateButton.Visibility = Visibility.Collapsed;
				}
			} catch (Exception ex) {
				logger.Error(ex, "unexpected error in update check: {0}", ex.Message);
			}
			CheckForUpdate.IsEnabled = true;
		}

		async private void TriggerUpdate_Click(object sender, RoutedEventArgs e) {
			try {
				CheckForUpdate.IsEnabled = false;
				TriggerUpdateButton.IsEnabled = false;
				CheckForUpdateStatus.Content = "Requesting automatic update...";
				var monitorClient = (MonitorClient)Application.Current.Properties["MonitorClient"];
				var r = await monitorClient.TriggerUpdate();
				CheckForUpdateStatus.Content = "Automatic update requested...";
				checkResponse(r, "Error When Triggering Update", "An error occurred while trying to trigger the update.");
			} catch (Exception ex) {
				logger.Error(ex, "unexpected error in update check: {0}", ex.Message);
			}
			TriggerUpdateButton.IsEnabled = true;
			CheckForUpdate.IsEnabled = true;
		}

		public void SetupIdList(ZitiIdentity[] ids) {
			IdListView.Children.Clear();
			for (int i=0; i<ids.Length; i++) {
				MenuIdentityItem item = new MenuIdentityItem();
				item.HorizontalAlignment = System.Windows.HorizontalAlignment.Stretch;
				item.Label = ids[i].Name;
				item.Identity = ids[i];
				item.ToggleSwitch.Enabled = ids[i].IsEnabled;
				IdListView.Children.Add(item);
			}
		}

		public void SetAppUpgradeAvailableText(string msg) {
			this.Dispatcher.Invoke(() => {
				VersionOlder.Content = msg;
				VersionNewer.Content = "";
				VersionOlder.Visibility = Visibility.Visible;
				VersionNewer.Visibility = Visibility.Collapsed;
			});
		}
		public void SetAppIsNewer(string msg) {
			this.Dispatcher.Invoke(() => {
				VersionNewer.Content = msg;
				VersionOlder.Content = "";
				VersionNewer.Visibility = Visibility.Visible;
				VersionOlder.Visibility = Visibility.Collapsed;
			});
		}
	}
}