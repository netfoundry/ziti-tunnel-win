﻿using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;
using System.IO;
using System.ServiceProcess;
using System.Linq;
using System.Diagnostics;
using System.Windows.Controls;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Animation;
using System.Web;

using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.DataStructures;
using ZitiDesktopEdge.ServiceClient;
using ZitiDesktopEdge.Utility;

using NLog;
using NLog.Config;
using NLog.Targets;
using Microsoft.Win32;

using System.Windows.Interop;

namespace ZitiDesktopEdge {

	public partial class MainWindow : Window {
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public string RECOVER = "RECOVER";
		public System.Windows.Forms.NotifyIcon notifyIcon;
		public string Position = "Bottom";
		private DateTime _startDate;
		private System.Windows.Forms.Timer _tunnelUptimeTimer;
		private DataClient serviceClient = null;
		MonitorClient monitorClient = null;
		private bool _isAttached = true;
		private bool _isServiceInError = false;
		private int _right = 75;
		private int _left = 75;
		private int _top = 30;
		private double _maxHeight = 800d;
		private string[] suffixes = { "Bps", "kBps", "mBps", "gBps", "tBps", "pBps" };

		private static SemaphoreSlim semaphoreSlim = new SemaphoreSlim(1, 1);

		static System.Reflection.Assembly asm = System.Reflection.Assembly.GetExecutingAssembly();

		public static string ThisAssemblyName;
		public static string ExecutionDirectory;
		public static string ExpectedLogPathRoot;
		public static string ExpectedLogPathUI;
		public static string ExpectedLogPathServices;

		static MainWindow() {
			asm = System.Reflection.Assembly.GetExecutingAssembly();
			ThisAssemblyName = asm.GetName().Name;
#if DEBUG
			ExecutionDirectory = @"C:\Program Files (x86)\NetFoundry, Inc\Ziti Desktop Edge";
#else
			ExecutionDirectory = Path.GetDirectoryName(asm.Location);
#endif
			ExpectedLogPathRoot = Path.Combine(ExecutionDirectory, "logs");
			ExpectedLogPathUI = Path.Combine(ExpectedLogPathRoot, "UI", $"{ThisAssemblyName}.log");
			ExpectedLogPathServices = Path.Combine(ExpectedLogPathRoot, "service", $"ziti-tunneler.log");
		}

		private void IdentityMenu_OnMessage(string message) {
			ShowBlurb(message, "");
		}

		private void SystemEvents_DisplaySettingsChanged(object sender, EventArgs e) {
			LoadIdentities(true);
		}

		private List<ZitiIdentity> identities {
			get {
				return (List<ZitiIdentity>)Application.Current.Properties["Identities"];
			}
		}

		/// <summary>
		/// The MFA Toggle was toggled
		/// </summary>
		/// <param name="isOn">True if the toggle was on</param>
		private async void MFAToggled(bool isOn) {
			if (isOn) {
				ShowLoad("Generating MFA", "MFA Setup Commencing, please wait");

				await serviceClient.EnableMFA(this.IdentityMenu.Identity.Fingerprint);
			} else {
				ShowBlurb("MFA Disabled, limited service access", "");
			}
		}

		/// <summary>
		/// When a Service Client is ready to setup the MFA Authorization
		/// </summary>
		/// <param name="sender">The service client</param>
		/// <param name="e">The MFA Event</param>
		private void ServiceClient_OnMfaEvent(object sender, MfaEvent mfa) {
			HideLoad();
			this.Dispatcher.Invoke(() => {
				if (mfa.Action == "enrollment_challenge") {
					string url = HttpUtility.UrlDecode(mfa.ProvisioningUrl);
					string secret = HttpUtility.ParseQueryString(url)["secret"];
					SetupMFA(this.IdentityMenu.Identity, url, secret);
				} else if (mfa.Action == "auth_challenge") {
					ShowBlurb("Setting Up auth_challenge", "");
				} else {
					ShowBlurb("Error Setting Up MFA", mfa.Op);
				}
			});
		}

		/// <summary>
		/// Show the MFA Setup Modal
		/// </summary>
		/// <param name="identity">The Ziti Identity to Setup</param>
		public void SetupMFA(ZitiIdentity identity, string url, string secret) {
			MFASetup.Opacity = 0;
			MFASetup.Visibility = Visibility.Visible;
			MFASetup.Margin = new Thickness(0, 0, 0, 0);
			MFASetup.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
			MFASetup.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));
			MFASetup.ShowSetup(identity, url, secret);
			ShowModal();
		}

		/// <summary>
		/// Show the MFA Authentication Screen when it is time to authenticate
		/// </summary>
		/// <param name="identity">The Ziti Identity to Authenticate</param>
		public void MFAAuthenticate(ZitiIdentity identity) {
			MFASetup.Opacity = 0;
			MFASetup.Visibility = Visibility.Visible;
			MFASetup.Margin = new Thickness(0, 0, 0, 0);
			MFASetup.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
			MFASetup.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));

			MFASetup.ShowMFA(identity);

			ShowModal();
		}

		/// <summary>
		/// Show the MFA Recovery Codes
		/// </summary>
		/// <param name="identity">The Ziti Identity to Authenticate</param>
		public void ShowMFARecoveryCodes(ZitiIdentity identity) {
			if (identity.MFAInfo!=null) {
				if (identity.MFAInfo.RecoveryCodes.Length > 0) {
					MFASetup.Opacity = 0;
					MFASetup.Visibility = Visibility.Visible;
					MFASetup.Margin = new Thickness(0, 0, 0, 0);
					MFASetup.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
					MFASetup.BeginAnimation(Grid.MarginProperty, new ThicknessAnimation(new Thickness(30, 30, 30, 30), TimeSpan.FromSeconds(.3)));

					MFASetup.ShowRecovery(identity.MFAInfo.RecoveryCodes, identity);

					ShowModal();
				} else {
					ShowBlurb("You do not have anymore recovery codes", this.RECOVER);
				}
			} else {
				ShowBlurb("MFA is not setup on this Identity", "");
			}
		}

		/// <summary>
		/// Show the modal, aniimating opacity
		/// </summary>
		private void ShowModal() {
			ModalBg.Visibility = Visibility.Visible;
			ModalBg.Opacity = 0;
			ModalBg.BeginAnimation(Grid.OpacityProperty, new DoubleAnimation(.8, TimeSpan.FromSeconds(.3)));
		}

		/// <summary>
		/// Close the various MFA windows
		/// </summary>
		/// <param name="sender">The close button</param>
		/// <param name="e">The event arguments</param>
		private void CloseComplete(object sender, EventArgs e) {
			MFASetup.Visibility = Visibility.Collapsed;
		}

		/// <summary>
		/// Hide the modal animating the opacity
		/// </summary>
		private void HideModal() {
			DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
			animation.Completed += ModalHideComplete;
			ModalBg.BeginAnimation(Grid.OpacityProperty, animation);
		}

		/// <summary>
		/// When the animation completes, set the visibility to avoid UI object conflicts
		/// </summary>
		/// <param name="sender">The animation</param>
		/// <param name="e">The event</param>
		private void ModalHideComplete(object sender, EventArgs e) {
			ModalBg.Visibility = Visibility.Collapsed;
		}

		/// <summary>
		/// Close the MFA Screen with animation
		/// </summary>
		/// <param name="isComplete"></param>
		private void DoClose(bool isComplete) {
			DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
			ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(0, 0, 0, 0), TimeSpan.FromSeconds(.3));
			animation.Completed += CloseComplete;
			MFASetup.BeginAnimation(Grid.OpacityProperty, animation);
			MFASetup.BeginAnimation(Grid.MarginProperty, animateThick);
			HideModal();
		}

		private void AddIdentity(ZitiIdentity id) {
			semaphoreSlim.Wait();
			if (!identities.Any(i => id.Fingerprint == i.Fingerprint)) {
				identities.Add(id);
			}
			semaphoreSlim.Release();
		}

		private System.Windows.Forms.ContextMenu contextMenu;
		private System.Windows.Forms.MenuItem contextMenuItem;
		private System.ComponentModel.IContainer components;
		public MainWindow() {
			InitializeComponent();
			SystemEvents.DisplaySettingsChanged += SystemEvents_DisplaySettingsChanged;
			string nlogFile = Path.Combine(ExecutionDirectory, ThisAssemblyName + "-log.config");

			bool byFile = false;
			if (File.Exists(nlogFile)) {
				LogManager.Configuration = new XmlLoggingConfiguration(nlogFile);
				byFile = true;
			} else {
				var config = new LoggingConfiguration();
				// Targets where to log to: File and Console
				var logfile = new FileTarget("logfile") {
					FileName = ExpectedLogPathUI,
					ArchiveEvery = FileArchivePeriod.Day,
					ArchiveNumbering = ArchiveNumberingMode.Rolling,
					MaxArchiveFiles = 7,
					Layout = "[${date:format=yyyy-MM-ddTHH:mm:ss.fff}Z] ${level:uppercase=true:padding=5}\t${logger}\t${message}\t${exception:format=tostring}",
				};
				var logconsole = new ConsoleTarget("logconsole");

				// Rules for mapping loggers to targets            
				config.AddRule(LogLevel.Debug, LogLevel.Fatal, logconsole);
				config.AddRule(LogLevel.Debug, LogLevel.Fatal, logfile);

				// Apply config           
				LogManager.Configuration = config;
			}
			logger.Info("============================== UI started ==============================");
			logger.Info("logger initialized");
			logger.Info("    - version   : {0}", asm.GetName().Version.ToString());
			logger.Info("    - using file: {0}", byFile);
			logger.Info("========================================================================");

			App.Current.MainWindow.WindowState = WindowState.Normal;
			App.Current.MainWindow.Closing += MainWindow_Closing;
			App.Current.MainWindow.Deactivated += MainWindow_Deactivated;
			App.Current.MainWindow.Activated += MainWindow_Activated;


			this.components = new System.ComponentModel.Container();
			this.contextMenu = new System.Windows.Forms.ContextMenu();
			this.contextMenuItem = new System.Windows.Forms.MenuItem();
			this.contextMenu.MenuItems.AddRange(new System.Windows.Forms.MenuItem[] { this.contextMenuItem });

			this.contextMenuItem.Index = 0;
			this.contextMenuItem.Text = "&Close UI";
			this.contextMenuItem.Click += new System.EventHandler(this.contextMenuItem_Click);


			notifyIcon = new System.Windows.Forms.NotifyIcon();
			notifyIcon.Visible = true;
			notifyIcon.Click += TargetNotifyIcon_Click;
			notifyIcon.Visible = true;
			notifyIcon.BalloonTipClosed += NotifyIcon_BalloonTipClosed;
			notifyIcon.MouseClick += NotifyIcon_MouseClick;
			notifyIcon.ContextMenu = this.contextMenu;

			IdentityMenu.OnDetach += OnDetach;
			MainMenu.OnDetach += OnDetach;

			this.MainMenu.MainWindow = this;
			this.IdentityMenu.MainWindow = this;
			SetNotifyIcon("white");

			IdentityMenu.OnMessage += IdentityMenu_OnMessage;
		}
		private void contextMenuItem_Click(object Sender, EventArgs e) {
			this.Close();
		}

		private void NotifyIcon_MouseClick(object sender, System.Windows.Forms.MouseEventArgs e) {
			if (e.Button == System.Windows.Forms.MouseButtons.Left) {
				System.Windows.Forms.MouseEventArgs mea = (System.Windows.Forms.MouseEventArgs)e;
				this.Show();
				this.Activate();
				//Do the awesome left clickness
			} else if (e.Button == System.Windows.Forms.MouseButtons.Right) {
				//Do the wickedy right clickness
			} else {
				//Some other button from the enum :)
			}
		}

        private void NotifyIcon_BalloonTipClosed(object sender, EventArgs e) {
			var thisIcon = (System.Windows.Forms.NotifyIcon)sender;
			thisIcon.Visible = false;
			thisIcon.Dispose();
		}

        private void Window_MouseDown(object sender, MouseButtonEventArgs e) {
			OnDetach(e);
		}

		private void OnDetach(MouseButtonEventArgs e) {
			if (e.ChangedButton == MouseButton.Left) {
				_isAttached = false;
				IdentityMenu.Arrow.Visibility = Visibility.Collapsed;
				Arrow.Visibility = Visibility.Collapsed;
				MainMenu.Detach();
				this.DragMove();
			}
		}

		private void MainWindow_Activated(object sender, EventArgs e) {
			this.Visibility = Visibility.Visible;
			Placement();
		}

		private void MainWindow_Deactivated(object sender, EventArgs e) {
			if (this._isAttached) {
#if DEBUG
				logger.Debug("debug is enabled - windows pinned");
				this.Visibility = Visibility.Collapsed;
#else
				this.Visibility = Visibility.Collapsed;
#endif
			}
		}

		private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e) {
			if (notifyIcon != null) {
				notifyIcon.Visible = false;
				notifyIcon.Icon.Dispose();
				notifyIcon.Dispose();
				notifyIcon = null;
			}
			Application.Current.Shutdown();
		}

		private void SetCantDisplay(string title, string detailMessage, Visibility closeButtonVisibility) {
			this.Dispatcher.Invoke(() => {
				NoServiceView.Visibility = Visibility.Visible;
				CloseErrorButton.IsEnabled = true;
				CloseErrorButton.Visibility = closeButtonVisibility;
				ErrorMsg.Content = title;
				ErrorMsgDetail.Content = detailMessage;
				SetNotifyIcon("red");
				_isServiceInError = true;
				UpdateServiceView();
			});
		}

		private void TargetNotifyIcon_Click(object sender, EventArgs e) {
//			this.Show();
//			System.Windows.Forms.MouseEventArgs mea = (System.Windows.Forms.MouseEventArgs)e;
			/*if (mea.cli mea.RightButton) {
			} else {
				
			}*/
//			this.Activate();
		}

		private void UpdateServiceView() {
			if (_isServiceInError) {
				AddIdAreaButton.Opacity = 0.1;
				AddIdAreaButton.IsEnabled = false;
				AddIdButton.Opacity = 0.1;
				AddIdButton.IsEnabled = false;
				ConnectButton.Opacity = 0.1;
				StatArea.Opacity = 0.1;
			} else {
				AddIdAreaButton.Opacity = 1.0;
				AddIdAreaButton.IsEnabled = true;
				AddIdButton.Opacity = 1.0;
				AddIdButton.IsEnabled = true;
				StatArea.Opacity = 1.0;
				ConnectButton.Opacity = 1.0;
			}
			TunnelConnected(!_isServiceInError);
		}

		private void App_ReceiveString(string obj) {
			Console.WriteLine(obj);
			this.Show();
			this.Activate();
		}

		async private void MainWindow_Loaded(object sender, RoutedEventArgs e) {

			Window window = Window.GetWindow(App.Current.MainWindow);
			ZitiDesktopEdge.App app = (ZitiDesktopEdge.App)App.Current;
			app.ReceiveString += App_ReceiveString;

			// add a new service client
			serviceClient = new DataClient();
			serviceClient.OnClientConnected += ServiceClient_OnClientConnected;
			serviceClient.OnClientDisconnected += ServiceClient_OnClientDisconnected;
			serviceClient.OnIdentityEvent += ServiceClient_OnIdentityEvent;
			serviceClient.OnMetricsEvent += ServiceClient_OnMetricsEvent;
			serviceClient.OnServiceEvent += ServiceClient_OnServiceEvent;
			serviceClient.OnTunnelStatusEvent += ServiceClient_OnTunnelStatusEvent;
			serviceClient.OnMfaEvent += ServiceClient_OnMfaEvent;
			Application.Current.Properties.Add("ServiceClient", serviceClient);

			monitorClient = new MonitorClient();
			monitorClient.OnClientConnected += MonitorClient_OnClientConnected;
            monitorClient.OnServiceStatusEvent += MonitorClient_OnServiceStatusEvent;
            monitorClient.OnShutdownEvent += MonitorClient_OnShutdownEvent;
            monitorClient.OnReconnectFailure += MonitorClient_OnReconnectFailure;
			Application.Current.Properties.Add("MonitorClient", monitorClient);

			Application.Current.Properties.Add("Identities", new List<ZitiIdentity>());
			MainMenu.OnAttachmentChange += AttachmentChanged;
			MainMenu.OnLogLevelChanged += LogLevelChanged;
			IdentityMenu.OnError += IdentityMenu_OnError;

			try {
				await serviceClient.ConnectAsync();
				await serviceClient.WaitForConnectionAsync();
			} catch /*ignored for now (Exception ex) */{
				ShowServiceNotStarted();
				serviceClient.Reconnect();
			}

			try {
				await monitorClient.ConnectAsync();
				await monitorClient.WaitForConnectionAsync();
			} catch /*ignored for now (Exception ex) */{
				monitorClient.Reconnect();
			}

			IdentityMenu.OnForgot += IdentityForgotten;
			Placement();
		}

        string nextVersionStr  = null;
        private void MonitorClient_OnReconnectFailure(object sender, object e) {
            if (nextVersionStr == null) {
				// check for the current version
				nextVersionStr = "checking for update";
				Version nextVersion = VersionUtil.NormalizeVersion(GithubAPI.GetVersion(GithubAPI.GetJson(GithubAPI.ProdUrl)));
				nextVersionStr = nextVersion.ToString();
				Version currentVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version; //fetch from ziti?

				int compare = currentVersion.CompareTo(nextVersion);
				if (compare < 0) {
					MainMenu.SetAppUpgradeAvailableText("Upgrade available: " + nextVersionStr);
					logger.Info("upgrade is available. Published version: {} is newer than the current version: {}", nextVersion, currentVersion);
					//UpgradeAvailable();
				} else if (compare > 0) {
					logger.Info("the version installed: {0} is newer than the released version: {1}", currentVersion, nextVersion);
					MainMenu.SetAppIsNewer("This version is newer than the latest: " + nextVersionStr);
				} else {
					logger.Info("Current version installed: {0} is the same as the latest released version {1}", currentVersion, nextVersion);
					MainMenu.SetAppUpgradeAvailableText("");
				}
			}
        }

        private void MonitorClient_OnShutdownEvent(object sender, StatusEvent e) {
			Application.Current.Shutdown();
		}

		private void MonitorClient_OnServiceStatusEvent(object sender, MonitorServiceStatusEvent evt) {
			try {
				if (evt.Message?.ToLower() == "upgrading") {
					logger.Info("The monitor has indicated an upgrade is in progress. Shutting down the UI");
					notifyIcon.Visible = false;
					notifyIcon.Icon.Dispose();
					notifyIcon.Dispose();
					Application.Current.Shutdown();
				}
				logger.Debug("MonitorClient_OnServiceStatusEvent: {0}", evt.Status);
				Application.Current.Properties["ReleaseStream"] = evt.ReleaseStream;
				ServiceControllerStatus status = (ServiceControllerStatus)Enum.Parse(typeof(ServiceControllerStatus), evt.Status);

				switch (status) {
					case ServiceControllerStatus.Running:
						logger.Info("Service is started");
						break;
					case ServiceControllerStatus.Stopped:
						logger.Info("Service is stopped");
						ShowServiceNotStarted();
						break;
					case ServiceControllerStatus.StopPending:
						logger.Info("Service is stopping...");

						this.Dispatcher.Invoke(async () => {
							SetCantDisplay("The Service is Stopping", "Please wait while the service stops", Visibility.Hidden);
							await WaitForServiceToStop(DateTime.Now + TimeSpan.FromSeconds(30));
						});
						break;
					case ServiceControllerStatus.StartPending:
						logger.Info("Service is starting...");
						break;
					case ServiceControllerStatus.PausePending:
						logger.Warn("UNEXPECTED STATUS: PausePending");
						break;
					case ServiceControllerStatus.Paused:
						logger.Warn("UNEXPECTED STATUS: Paused");
						break;
					default:
						logger.Warn("UNEXPECTED STATUS: {0}", evt.Status);
						break;
				}
			} catch (Exception ex) {
				logger.Warn(ex, "unexpected exception in MonitorClient_OnShutdownEvent? {0}", ex.Message);
			}
		}

		async private Task WaitForServiceToStop(DateTime until) {
			//continually poll for the service to stop. If it is stuck - ask the user if they want to try to force
			//close the service
			while (DateTime.Now < until) {
				await Task.Delay(2000);
				MonitorServiceStatusEvent resp = await monitorClient.StatusAsync();
				if (resp.IsStopped()) {
					// good - that's what we are waiting for...
					return;
				} else {
					// bad - not stopped yet...
					logger.Debug("Waiting for service to stop... Still not stopped yet. Status: {0}", resp.Status);
				}
			}
			// real bad - means it's stuck probably. Ask the user if they want to try to force it...
			logger.Warn("Waiting for service to stop... Service did not reach stopped state in the expected amount of time.");
			SetCantDisplay("The Service Appears Stuck", "Would you like to try to force close the service?", Visibility.Visible);
			CloseErrorButton.Content = "Force Quit";
			CloseErrorButton.Click -= CloseError;
			CloseErrorButton.Click += ForceQuitButtonClick;
		}

		async private void ForceQuitButtonClick(object sender, RoutedEventArgs e) {
			MonitorServiceStatusEvent status = await monitorClient.ForceTerminateAsync();
			if (status.IsStopped()) {
				//good
				CloseErrorButton.Click += CloseError; //reset the close button...
				CloseErrorButton.Click -= ForceQuitButtonClick;
			} else {
				//bad...
				SetCantDisplay("The Service Is Still Running", "Current status is: " + status.Status, Visibility.Visible);
			}
		}

		async private void StartZitiService(object sender, RoutedEventArgs e) {
			try {
				ShowLoad("Starting", "Starting the data service");
				logger.Info("StartZitiService");
				var r = await monitorClient.StartServiceAsync();
				if (r.Code != 0) {
					logger.Debug("ERROR: {0} : {1}", r.Message, r.Error);
				} else {
					logger.Info("Service started!");
					//no longer used: startZitiButtonVisible = false;
					CloseErrorButton.Click -= StartZitiService;
					CloseError(null, null);
				}
			} catch (Exception ex) {
				logger.Info(ex, "UNEXPECTED ERROR!");
				//no longer used: startZitiButtonVisible = false;
				//CloseErrorButton.Click += StartZitiService;
				CloseErrorButton.IsEnabled = true;
			}
			CloseErrorButton.IsEnabled = true;
			HideLoad();
		}

		private void ShowServiceNotStarted() {
			TunnelConnected(false);
			LoadIdentities(true);
			/*
			this.Dispatcher.Invoke(() => {
				semaphoreSlim.Wait(); //make sure the event is only added to the button once
				CloseErrorButton.Click -= CloseError;
				if (!startZitiButtonVisible) {
					CloseErrorButton.Content = "Start Service";
					startZitiButtonVisible = true;
					CloseErrorButton.Click += StartZitiService;
				}
				semaphoreSlim.Release();
				SetCantDisplay("Service Not Started", "Do you want to start the data service now?", Visibility.Visible);
			});
			*/
		}

		private void MonitorClient_OnClientConnected(object sender, object e) {
			logger.Debug("MonitorClient_OnClientConnected");
			MainMenu.SetAppUpgradeAvailableText("");
		}

		async private void LogLevelChanged(string level) {
			await serviceClient.SetLogLevelAsync(level);
			await monitorClient.SetLogLevelAsync(level);
			Ziti.Desktop.Edge.Utils.UIUtils.SetLogLevel(level);
		}

		private void IdentityMenu_OnError(string message) {
			ShowError("Identity Error", message);
		}

		private void ServiceClient_OnClientConnected(object sender, object e) {
			this.Dispatcher.Invoke(() => {
				//e is _ALWAYS_ null at this time use this to display something if you want
				NoServiceView.Visibility = Visibility.Collapsed;
				_isServiceInError = false;
				UpdateServiceView();
				SetNotifyIcon("white");
				LoadIdentities(true);
			});
		}

		private void ServiceClient_OnClientDisconnected(object sender, object e) {
			this.Dispatcher.Invoke(() => {
				IdList.Children.Clear();
				if (e != null) {
					logger.Debug(e.ToString());
				}
				//SetCantDisplay("Start the Ziti Tunnel Service to continue");
				ShowServiceNotStarted();
			});
		}

		private void ServiceClient_OnIdentityEvent(object sender, IdentityEvent e) {
			if (e == null) return;

			ZitiIdentity zid = ZitiIdentity.FromClient(e.Id);
			logger.Debug($"==== IdentityEvent    : action:{e.Action} fingerprint:{e.Id.FingerPrint} name:{e.Id.Name} ");

			this.Dispatcher.Invoke(() => {
				if (e.Action == "added") {
					var found = identities.Find(i => i.Fingerprint == e.Id.FingerPrint);
					if (found == null) {
						AddIdentity(zid);
						LoadIdentities(true);
					} else {
						// means we likely are getting an update for some reason. compare the identities and use the latest info
						found.Name = zid.Name;
						found.ControllerUrl = zid.ControllerUrl;
						found.IsEnabled = zid.IsEnabled;
						return;
					}
				} else {
					IdentityForgotten(ZitiIdentity.FromClient(e.Id));
				}
			});
			logger.Debug($"IDENTITY EVENT. Action: {e.Action} fingerprint: {zid.Fingerprint}");
		}

		private void ServiceClient_OnMetricsEvent(object sender, List<Identity> ids) {
			if (ids != null) {
				long totalUp = 0;
				long totalDown = 0;
				foreach (var id in ids) {
					//logger.Debug($"==== MetricsEvent     : id {id.Name} down: {id.Metrics.Down} up:{id.Metrics.Up}");
					if (id?.Metrics != null) {
						totalDown += id.Metrics.Down;
						totalUp += id.Metrics.Up;
					}
				}
				this.Dispatcher.Invoke(() => {
					SetSpeed(totalUp, UploadSpeed, UploadSpeedLabel);
					SetSpeed(totalDown, DownloadSpeed, DownloadSpeedLabel);
				});
			}
		}

		public void SetSpeed(decimal bytes, Label speed, Label speedLabel) {
			int counter = 0;
			while (Math.Round(bytes / 1024) >= 1) {
				bytes = bytes / 1024;
				counter++;
			}
			speed.Content = bytes.ToString("0.0");
			speedLabel.Content = suffixes[counter];
		}

		private void ServiceClient_OnServiceEvent(object sender, ServiceEvent e) {
			if (e == null) return;

			Debug.WriteLine($"==== ServiceEvent     : action:{e.Action} fingerprint:{e.Fingerprint} name:{e.Service.Name} ");
			this.Dispatcher.Invoke(() => {
				var found = identities.Find(id => id.Fingerprint == e.Fingerprint);

				if (found == null) {
					Debug.WriteLine($"{e.Action} service event for {e.Service.Name} but the provided identity fingerprint {e.Fingerprint} is not found!");
					return;
				}

				if (e.Action == "added") {
					ZitiService zs = new ZitiService(e.Service);
					var svc = found.Services.Find(s => s.Name == zs.Name);
					if (svc == null) {
						found.Services.Add(zs);
					} else {
						logger.Debug("the service named " + zs.Name + " is already accounted for on this identity.");
					}
				} else {
					logger.Debug("removing the service named: " + e.Service.Name);
					found.Services.RemoveAll(s => s.Name == e.Service.Name);
				}
				LoadIdentities(false);
				IdentityDetails deets = ((MainWindow)Application.Current.MainWindow).IdentityMenu;
				if (deets.IsVisible) {
					deets.UpdateView();
				}
			});
		}

		private void ServiceClient_OnTunnelStatusEvent(object sender, TunnelStatusEvent e) {
			if (e == null) return; //just skip it for now...
			logger.Debug($"==== TunnelStatusEvent: ");
			Application.Current.Properties.Remove("CurrentTunnelStatus");
			Application.Current.Properties.Add("CurrentTunnelStatus", e.Status);
			e.Status.Dump(Console.Out);
			this.Dispatcher.Invoke(() => {
				if (e.ApiVersion != DataClient.EXPECTED_API_VERSION) {
					SetCantDisplay("Version mismatch!", "The version of the Service is not compatible", Visibility.Visible);
					return;
				}
				this.MainMenu.LogLevel = e.Status.LogLevel;
				Ziti.Desktop.Edge.Utils.UIUtils.SetLogLevel(e.Status.LogLevel);

				InitializeTimer((int)e.Status.Duration);
				LoadStatusFromService(e.Status);
				LoadIdentities(true);

				IdentityDetails deets = ((MainWindow)Application.Current.MainWindow).IdentityMenu;
				if (deets.IsVisible) {
					deets.UpdateView();
				}
			});
		}

		private void IdentityForgotten(ZitiIdentity forgotten) {
			ZitiIdentity idToRemove = null;
			foreach (var id in identities) {
				if (id.Fingerprint == forgotten.Fingerprint) {
					idToRemove = id;
					break;
				}
			}
			identities.Remove(idToRemove);
			LoadIdentities(false);
		}

		private void AttachmentChanged(bool attached) {
			_isAttached = attached;
			if (!_isAttached) {
				SetLocation();
			}
			Placement();
			MainMenu.Visibility = Visibility.Collapsed;
		}

		private void LoadStatusFromService(TunnelStatus status) {
			//clear any identities
			this.identities.Clear();

			if (status != null) {
				_isServiceInError = false;
				UpdateServiceView();
				NoServiceView.Visibility = Visibility.Collapsed;
				if (status.Active) {
					SetNotifyIcon("green");
				} else {
					SetNotifyIcon("white");
				}
				if (!Application.Current.Properties.Contains("ip")) {
					Application.Current.Properties.Add("ip", status?.IpInfo?.Ip);
				}
				if (!Application.Current.Properties.Contains("subnet")) {
					Application.Current.Properties.Add("subnet", status?.IpInfo?.Subnet);
				}
				if (!Application.Current.Properties.Contains("mtu")) {
					Application.Current.Properties.Add("mtu", status?.IpInfo?.MTU);
				}
				if (!Application.Current.Properties.Contains("dns")) {
					Application.Current.Properties.Add("dns", status?.IpInfo?.DNS);
				}

				foreach (var id in status.Identities) {
					updateViewWithIdentity(id);
				}
				LoadIdentities(true);
			} else {
				ShowServiceNotStarted();
			}
		}

		private void updateViewWithIdentity(Identity id) {
			var zid = ZitiIdentity.FromClient(id);
			foreach (var i in identities) {
				if (i.Fingerprint == zid.Fingerprint) {
					identities.Remove(i);
					break;
				}
			}
			identities.Add(zid);
		}
		private void SetNotifyIcon(string iconPrefix) {
			var iconUri = new Uri("pack://application:,,/Assets/Images/ziti-" + iconPrefix + ".ico");
			Stream iconStream = Application.GetResourceStream(iconUri).Stream;
			notifyIcon.Icon = new Icon(iconStream);

			Application.Current.MainWindow.Icon = System.Windows.Media.Imaging.BitmapFrame.Create(iconUri);
		}

		private void LoadIdentities(Boolean repaint) {
			IdList.Children.Clear();
			IdList.Height = 0;
			var desktopWorkingArea = SystemParameters.WorkArea;
			if (_maxHeight > (desktopWorkingArea.Height - 10)) _maxHeight = desktopWorkingArea.Height - 10;
			if (_maxHeight < 100) _maxHeight = 100;
			IdList.MaxHeight = _maxHeight - 520;
			ZitiIdentity[] ids = identities.OrderBy(i => i.Name.ToLower()).ToArray();
			MainMenu.SetupIdList(ids);

			if (ids.Length > 0 && serviceClient.Connected) {
				double height = 490 + (ids.Length * 60);
				if (height > _maxHeight) height = _maxHeight;
				this.Height = height;
				IdentityMenu.SetHeight(this.Height - 160);
				MainMenu.IdentitiesButton.Visibility = Visibility.Visible;
				foreach (var id in ids) {
					IdentityItem idItem = new IdentityItem();

					idItem.ToggleStatus.IsEnabled = id.IsEnabled;
					if (id.IsEnabled) {
						idItem.ToggleStatus.Content = "ENABLED";
					} else {
						idItem.ToggleStatus.Content = "DISABLED";
					}
					idItem.OnStatusChanged += Id_OnStatusChanged;
					idItem.Identity = id;
					IdList.Children.Add(idItem);
				}
				//IdList.Height = ;
				DoubleAnimation animation = new DoubleAnimation((double)(ids.Length * 64), TimeSpan.FromSeconds(.3));
				IdList.BeginAnimation(FrameworkElement.HeightProperty, animation);
				IdListScroller.Visibility = Visibility.Visible;
			} else {
				this.Height = 490;
				MainMenu.IdentitiesButton.Visibility = Visibility.Collapsed;
				IdListScroller.Visibility = Visibility.Collapsed;
			}
			AddIdButton.Visibility = Visibility.Visible;
			AddIdAreaButton.Visibility = Visibility.Visible;

			Placement();
		}

		private void Id_OnStatusChanged(bool attached) {
			for (int i = 0; i < IdList.Children.Count; i++) {
				IdentityItem item = IdList.Children[i] as IdentityItem;
				if (item.ToggleSwitch.Enabled) {
					break;
				}
			}
		}

		private void TunnelConnected(bool isConnected) {
			if (isConnected) {
				ConnectButton.Visibility = Visibility.Collapsed;
				DisconnectButton.Visibility = Visibility.Visible;
			} else {
				ConnectButton.Visibility = Visibility.Visible;
				DisconnectButton.Visibility = Visibility.Collapsed;
			}
		}

		private void SetLocation() {
			var desktopWorkingArea = SystemParameters.WorkArea;

			var height = MainView.ActualHeight;
			IdentityMenu.MainHeight = MainView.ActualHeight;
			MainMenu.MainHeight = MainView.ActualHeight;

			Rectangle trayRectangle = WinAPI.GetTrayRectangle();
			if (trayRectangle.Top < 20) {
				this.Position = "Top";
				this.Top = desktopWorkingArea.Top + _top;
				this.Left = desktopWorkingArea.Right - this.Width - _right;
				Arrow.SetValue(Canvas.TopProperty, (double)0);
				Arrow.SetValue(Canvas.LeftProperty, (double)185);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, (double)0);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, (double)0);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
			} else if (trayRectangle.Left < 20) {
				this.Position = "Left";
				this.Left = _left;
				this.Top = desktopWorkingArea.Bottom - this.ActualHeight - 75;
				Arrow.SetValue(Canvas.TopProperty, height - 200);
				Arrow.SetValue(Canvas.LeftProperty, (double)0);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, height - 200);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, (double)0);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, height - 200);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, (double)0);
			} else if (desktopWorkingArea.Right == (double)trayRectangle.Left) {
				this.Position = "Right";
				this.Left = desktopWorkingArea.Right - this.Width - 20;
				this.Top = desktopWorkingArea.Bottom - height - 75;
				Arrow.SetValue(Canvas.TopProperty, height - 100);
				Arrow.SetValue(Canvas.LeftProperty, this.Width - 30);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, height - 100);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, this.Width - 30);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, height - 100);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, this.Width - 30);
			} else {
				this.Position = "Bottom";
				this.Left = desktopWorkingArea.Right - this.Width - 75;
				this.Top = desktopWorkingArea.Bottom - height;
				Arrow.SetValue(Canvas.TopProperty, height - 35);
				Arrow.SetValue(Canvas.LeftProperty, (double)185);
				MainMenu.Arrow.SetValue(Canvas.TopProperty, height - 35);
				MainMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
				IdentityMenu.Arrow.SetValue(Canvas.TopProperty, height - 35);
				IdentityMenu.Arrow.SetValue(Canvas.LeftProperty, (double)185);
			}
		}
		public void Placement() {
			if (_isAttached) {
				Arrow.Visibility = Visibility.Visible;
				IdentityMenu.Arrow.Visibility = Visibility.Visible;
				SetLocation();
			} else {
				IdentityMenu.Arrow.Visibility = Visibility.Collapsed;
				Arrow.Visibility = Visibility.Collapsed;
			}
		}

		private void OpenIdentity(ZitiIdentity identity) {
			IdentityMenu.Identity = identity;

		}

		private void ShowMenu(object sender, MouseButtonEventArgs e) {
			MainMenu.Visibility = Visibility.Visible;
		}

		async private void AddIdentity(object sender, MouseButtonEventArgs e) {
			UIModel.HideOnLostFocus = false;
			Microsoft.Win32.OpenFileDialog jwtDialog = new Microsoft.Win32.OpenFileDialog();
			UIModel.HideOnLostFocus = true;
			jwtDialog.DefaultExt = ".jwt";
			jwtDialog.Filter = "Ziti Identities (*.jwt)|*.jwt";
			if (jwtDialog.ShowDialog() == true) {
				ShowLoad("Adding Identity", "Please wait while the identity is added");
				string fileContent = File.ReadAllText(jwtDialog.FileName);

				try {
					Identity createdId = await serviceClient.AddIdentityAsync(System.IO.Path.GetFileName(jwtDialog.FileName), false, fileContent);

					if (createdId != null) {
						var zid = ZitiIdentity.FromClient(createdId);
						AddIdentity(zid);
						LoadIdentities(true);
					} else {
						ShowError("Identity Error", "Identity Id was null, please try again");
					}
					await serviceClient.IdentityOnOffAsync(createdId.FingerPrint, true);
				} catch (ServiceException se) {
					ShowError("Error Occurred", se.Message + " " + se.AdditionalInfo);
				} catch (Exception ex) {
					ShowError("Unexpected Error", "Code 2:" + ex.Message);
				}
				HideLoad();
			}
		}

		private void OnTimedEvent(object sender, EventArgs e) {
			TimeSpan span = (DateTime.Now - _startDate);
			int hours = span.Hours;
			int minutes = span.Minutes;
			int seconds = span.Seconds;
			var hoursString = (hours > 9) ? hours.ToString() : "0" + hours;
			var minutesString = (minutes > 9) ? minutes.ToString() : "0" + minutes;
			var secondsString = (seconds > 9) ? seconds.ToString() : "0" + seconds;
			ConnectedTime.Content = hoursString + ":" + minutesString + ":" + secondsString;
		}

		private void InitializeTimer(int millisAgoStarted) {
			_startDate = DateTime.Now.Subtract(new TimeSpan(0, 0, 0, 0, millisAgoStarted));
			_tunnelUptimeTimer = new System.Windows.Forms.Timer();
			_tunnelUptimeTimer.Interval = 100;
			_tunnelUptimeTimer.Tick += OnTimedEvent;
			_tunnelUptimeTimer.Enabled = true;
			_tunnelUptimeTimer.Start();
		}

		async private Task DoConnectAsync() {
			try {
				SetNotifyIcon("green");
				TunnelConnected(true);

				for (int i = 0; i < identities.Count; i++) {
					await serviceClient.IdentityOnOffAsync(identities[i].Fingerprint, true);
				}
				for (int i = 0; i < IdList.Children.Count; i++) {
					IdentityItem item = IdList.Children[i] as IdentityItem;
					item._identity.IsEnabled = true;
					item.RefreshUI();
				}
			} catch (ServiceException se) {
				ShowError("Error Occurred", se.Message + " " + se.AdditionalInfo);
			} catch (Exception ex) {
				ShowError("Unexpected Error", "Code 3:" + ex.Message);
			}
		}

		async private void Disconnect(object sender, RoutedEventArgs e) {
			try {
				ShowLoad("Disabling Service", "Please wait for the service to stop.");
				var r = await monitorClient.StopServiceAsync();
				if (r.Code != 0) {
					logger.Warn("ERROR: Error:{0}, Message:{1}", r.Error, r.Message);
				} else {
					logger.Info("Service stopped!");
				}
			} catch(Exception ex) {
				logger.Error(ex, "unexpected error: {0}", ex.Message);
				ShowError("Erorr Disabling Service", "An error occurred while trying to disable the data service. Is the monitor service running?");
			}
			HideLoad();
		}

		internal void ShowLoad(string title, string msg) {
			this.Dispatcher.Invoke(() => {
				LoadingDetails.Text = msg;
				LoadingTitle.Content = title;
				LoadProgress.IsIndeterminate = true;
				LoadingScreen.Visibility = Visibility.Visible;
				UpdateLayout();
			});
		}

		internal void HideLoad() {
			this.Dispatcher.Invoke(() => {
				LoadingScreen.Visibility = Visibility.Collapsed;
				LoadProgress.IsIndeterminate = false;
			});
		}

		private void FormFadeOut_Completed(object sender, EventArgs e) {
			closeCompleted = true;
		}
		private bool closeCompleted = false;
		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e) {
			if (!closeCompleted) {
				FormFadeOut.Begin();
				e.Cancel = true;
			}
		}

		public void ShowError(String title, String message) {
			this.Dispatcher.Invoke(() => {
				ErrorTitle.Content = title;
				ErrorDetails.Text = message;
				ErrorView.Visibility = Visibility.Visible;
			});
		}

		private void CloseError(object sender, RoutedEventArgs e) {
			this.Dispatcher.Invoke(() => {
				ErrorView.Visibility = Visibility.Collapsed;
				NoServiceView.Visibility = Visibility.Collapsed;
				CloseErrorButton.IsEnabled = true;
			});
		}

		private void CloseApp(object sender, RoutedEventArgs e) {
			Application.Current.Shutdown();
		}

		private void MainUI_Deactivated(object sender, EventArgs e) {
			if (this._isAttached) {
#if DEBUG
				logger.Debug("debug is enabled - windows pinned");
#else
				this.Visibility = Visibility.Collapsed;
#endif
			}
		}

		private void Label_MouseDoubleClick(object sender, MouseButtonEventArgs e) {
			Placement();
		}

		int cur = 0;
		LogLevelEnum[] levels = new LogLevelEnum[] { LogLevelEnum.FATAL, LogLevelEnum.ERROR, LogLevelEnum.WARN, LogLevelEnum.INFO, LogLevelEnum.DEBUG, LogLevelEnum.TRACE, LogLevelEnum.VERBOSE };
		public LogLevelEnum NextLevel() {
			cur++;
			if (cur > 6) {
				cur = 0;
			}
			return levels[cur];
		}

		private void IdList_LayoutUpdated(object sender, EventArgs e) {
			Placement();
		}

		async private void CollectLogFileClick(object sender, RoutedEventArgs e) {
			await CollectLogFiles();
		}
		async private Task CollectLogFiles() {
			MonitorServiceStatusEvent resp = await monitorClient.CaptureLogsAsync();
			if (resp != null) {

				logger.Info("response: {0}", resp.Message);
			} else {
				ShowError("Error Collecting Feedback", "An error occurred while trying to gather feedback. Is the monitor service running?");
            }
		}

		private string _blurbUrl = "";

		/// <summary>
		/// Show the blurb as a growler notification
		/// </summary>
		/// <param name="message">The message to show</param>
		/// <param name="url">The url or action name to execute</param>
		public void ShowBlurb(string message, string url) {
			Blurb.Content = message;
			_blurbUrl = url;
			BlurbArea.Visibility = Visibility.Visible;
			BlurbArea.Opacity = 0;
			BlurbArea.Margin = new Thickness(0, 0, 0, 0);
			DoubleAnimation animation = new DoubleAnimation(1, TimeSpan.FromSeconds(.3));
			ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(15, 0, 15, 15), TimeSpan.FromSeconds(.3));
			BlurbArea.BeginAnimation(Grid.OpacityProperty, animation);
			BlurbArea.BeginAnimation(Grid.MarginProperty, animateThick);
		}

		/// <summary>
		/// Execute the hide operation wihout an action from the growler
		/// </summary>
		/// <param name="sender">The object that was clicked</param>
		/// <param name="e">The click event</param>
		private void DoHideBlurb(object sender, MouseButtonEventArgs e) {
			HideBlurb();
		}

		/// <summary>
		/// Hide the blurb area
		/// </summary>
		private void HideBlurb() {
			DoubleAnimation animation = new DoubleAnimation(0, TimeSpan.FromSeconds(.3));
			ThicknessAnimation animateThick = new ThicknessAnimation(new Thickness(0, 0, 0, 0), TimeSpan.FromSeconds(.3));
			animation.Completed += HideComplete;
			BlurbArea.BeginAnimation(Grid.OpacityProperty, animation);
			BlurbArea.BeginAnimation(Grid.MarginProperty, animateThick);
		}

		/// <summary>
		/// Hide the blurb area after the animation fades out
		/// </summary>
		/// <param name="sender">The animation object</param>
		/// <param name="e">The completion event</param>
		private void HideComplete(object sender, EventArgs e) {
			BlurbArea.Visibility = Visibility.Collapsed;
		}

		/// <summary>
		/// Execute a predefined action or url when the pop up is clicked
		/// </summary>
		/// <param name="sender">The object that was clicked</param>
		/// <param name="e">The click event</param>
		private void BlurbAction(object sender, MouseButtonEventArgs e) {
			if (_blurbUrl.Length>0) {
				// So this simply execute a url but you could do like if (_blurbUrl=="DoSomethingNifty") CallNifyFunction();
				if (_blurbUrl== this.RECOVER) {
					// clint: can we know what identity to execute recovery against?
				} else {
					Process.Start(new ProcessStartInfo(_blurbUrl) { UseShellExecute = true });
				}
			} else {
				HideBlurb();
			}
		}

		private void ShowAuthenticate(ZitiIdentity identity) {
			MFAAuthenticate(identity);
		}

		private void ShowRecovery(ZitiIdentity identity) {
			ShowMFARecoveryCodes(identity);
		}
	}
}
