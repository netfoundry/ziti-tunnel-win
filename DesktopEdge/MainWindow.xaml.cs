﻿using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;
using System.IO;
using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.ServiceClient;
using System.ServiceProcess;
using System.Linq;
using System.Diagnostics;
using System.Windows.Controls;
using System.Drawing;


namespace ZitiDesktopEdge {

	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow:Window {

		public System.Windows.Forms.NotifyIcon notifyIcon;
		public string Position = "Bottom";
		private DateTime _startDate;
		private System.Windows.Forms.Timer _timer;
		private Client serviceClient = null;
		private bool _isAttached = true;
		private bool _isServiceInError = false;
		private int _right = 75;
		private int _left = 75;
		private int _bottom = 0;
		private int _top = 30;
		private double _maxHeight = 800d;
		private string[] suffixes = { "bps", "kbps", "mbps", "gbps", "tbps", "pbps" };

		private List<ZitiIdentity> identities {
			get {
				return (List<ZitiIdentity>)Application.Current.Properties["Identities"];
			}
		}

		private void LaunchOrInstall() {
			ServiceController ctl = ServiceController.GetServices().FirstOrDefault(s => s.ServiceName=="ziti");
			if (ctl==null) {
				SetCantDisplay();
			} else {
				if (ctl.Status!=ServiceControllerStatus.Running) {
					try {
						ctl.Start();
					} catch (Exception e) {
						UILog.Log(e.Message);
						SetCantDisplay();
					}
				}
			}
		}

		private List<ZitiService> services = new List<ZitiService>();
		public MainWindow() {
			InitializeComponent();

			App.Current.MainWindow.WindowState = WindowState.Normal;
			App.Current.MainWindow.Closing += MainWindow_Closing;
			App.Current.MainWindow.Deactivated += MainWindow_Deactivated;
			App.Current.MainWindow.Activated += MainWindow_Activated;
			notifyIcon = new System.Windows.Forms.NotifyIcon();
			notifyIcon.Visible = true;
			notifyIcon.Click += TargetNotifyIcon_Click;
			notifyIcon.Visible = true;
			IdentityMenu.OnDetach += OnDetach;
			MainMenu.OnDetach += OnDetach;

			LaunchOrInstall();

			SetNotifyIcon("white");
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
				Debug.WriteLine("debug is enabled - windows pinned");
#else
				this.Visibility = Visibility.Collapsed;
#endif
			}
		}

		private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e) {
			notifyIcon.Visible = false;
			notifyIcon.Icon.Dispose();
			notifyIcon.Dispose();
		}
		
		private void SetCantDisplay(string msg, string detailMessage) {
			NoServiceView.Visibility = Visibility.Visible;
			ErrorMsg.Content = msg;
			ErrorMsgDetail.Content = detailMessage;
			SetNotifyIcon("red");
			_isServiceInError = true;
			UpdateServiceView();
		}
		private void SetCantDisplay() {
			SetCantDisplay("Service Not Started", "Start the Ziti Tunnel Service to get started");
		}

		private void TargetNotifyIcon_Click(object sender, EventArgs e) {
			this.Show();
			this.Activate();
		}

		private void UpdateServiceView() {
			if (_isServiceInError) {
				AddIdAreaButton.Opacity = 0.1;
				AddIdAreaButton.IsEnabled = false;
				AddIdButton.Opacity = 0.1;
				AddIdButton.IsEnabled = false;
				DisconnectButton.Visibility = Visibility.Collapsed;
				ConnectButton.Visibility = Visibility.Visible;
				ConnectButton.Opacity = 0.1;
				StatArea.Opacity = 0.1;
			} else {
				AddIdAreaButton.Opacity = 1.0;
				AddIdAreaButton.IsEnabled = true;
				AddIdButton.Opacity = 1.0;
				AddIdButton.IsEnabled = true;
				ConnectButton.Visibility = Visibility.Collapsed;
				DisconnectButton.Visibility = Visibility.Visible;
				StatArea.Opacity = 1.0;
				ConnectButton.Opacity = 1.0;
			}
		}

		private void MainWindow_Loaded(object sender, RoutedEventArgs e) {
			// add a new service client
			serviceClient = new Client();
			serviceClient.OnClientConnected += ServiceClient_OnClientConnected;
			serviceClient.OnClientDisconnected += ServiceClient_OnClientDisconnected;
			serviceClient.OnIdentityEvent += ServiceClient_OnIdentityEvent;
			serviceClient.OnMetricsEvent += ServiceClient_OnMetricsEvent;
			serviceClient.OnServiceEvent += ServiceClient_OnServiceEvent;
			serviceClient.OnTunnelStatusEvent += ServiceClient_OnTunnelStatusEvent;

			Application.Current.Properties.Add("ServiceClient", serviceClient);
			Application.Current.Properties.Add("Identities", new List<ZitiIdentity>());
			MainMenu.OnAttachmentChange += AttachmentChanged;
			MainMenu.OnLogLevelChanged += LogLevelChanged;
			IdentityMenu.OnError += IdentityMenu_OnError;

			try {
				serviceClient.Connect();
				//var s = serviceClient.GetStatus();
				//LoadStatusFromService(s.Status);
			} catch /*ignored for now (Exception ex) */{
				SetCantDisplay();
				serviceClient.Reconnect();
			}
			IdentityMenu.OnForgot += IdentityForgotten;
			Placement();
		}

		private void LogLevelChanged(string level) {
			serviceClient.SetLogLevel(level);
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
				SetCantDisplay();
			});
		}

		private void ServiceClient_OnIdentityEvent(object sender, IdentityEvent e) {
			if (e == null) return;

			ZitiIdentity zid = ZitiIdentity.FromClient(e.Id);
			Debug.WriteLine($"==== IdentityEvent    : action:{e.Action} fingerprint:{e.Id.FingerPrint} name:{e.Id.Name} ");

			this.Dispatcher.Invoke(() => {
				if (e.Action == "added") {
					var found = identities.Find(i => i.Fingerprint == e.Id.FingerPrint);
					if (found == null) {
						identities.Add(zid);
						LoadIdentities(true);
					} else {
						//if we get here exit out so that LoadIdentities() doesn't get called
						found.IsEnabled = true;
						return;
					}
				} else {
					IdentityForgotten(ZitiIdentity.FromClient(e.Id));
				}
			});
			Debug.WriteLine($"IDENTITY EVENT. Action: {e.Action} fingerprint: {zid.Fingerprint}");
		}

		private void ServiceClient_OnMetricsEvent(object sender, List<Identity> ids) {
			if (ids != null) {
				long totalUp = 0;
				long totalDown = 0;
				foreach (var id in ids) {
					//Debug.WriteLine($"==== MetricsEvent     : id {id.Name} down: {id.Metrics.Down} up:{id.Metrics.Up}");
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
					if (svc == null) found.Services.Add(zs);
					else Debug.WriteLine("the service named " + zs.Name + " is already accounted for on this identity.");
				} else {
					Debug.WriteLine("removing the service named: " + e.Service.Name);
					found.Services.RemoveAll(s => s.Name == e.Service.Name);
				}
				LoadIdentities(false);
			});
		}

		private void ServiceClient_OnTunnelStatusEvent(object sender, TunnelStatusEvent e) {
			if (e == null) return; //just skip it for now...
			Debug.WriteLine($"==== TunnelStatusEvent: ");
			Application.Current.Properties.Add("CurrentTunnelStatus", e.Status);
			e.Status.Dump(Console.Out);
			this.Dispatcher.Invoke(() => {
				if(e.ApiVersion != Client.EXPECTED_API_VERSION) {
					SetCantDisplay("Version mismatch!", "The version of the Service is not compatible");
					return;
                }
				this.MainMenu.LogLevel = e.Status.LogLevel;
				InitializeTimer((int)e.Status.Duration);
				LoadStatusFromService(e.Status);
				LoadIdentities(false);
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
				SetNotifyIcon("white");
				if (status.Active) {
					InitializeTimer((int)status.Duration);
					ConnectButton.Visibility = Visibility.Collapsed;
					DisconnectButton.Visibility = Visibility.Visible;
					SetNotifyIcon("green");
				} else {
					ConnectButton.Visibility = Visibility.Visible;
					DisconnectButton.Visibility = Visibility.Collapsed;
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
				SetCantDisplay();
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
			System.IO.Stream iconStream = System.Windows.Application.GetResourceStream(iconUri).Stream;
			notifyIcon.Icon = new System.Drawing.Icon(iconStream);

			Application.Current.MainWindow.Icon = System.Windows.Media.Imaging.BitmapFrame.Create(iconUri);
		}

		private void LoadIdentities(Boolean repaint) {
			IdList.Children.Clear();
			IdList.Height = 0;
			IdList.MaxHeight = _maxHeight-520;
			ZitiIdentity[] ids = identities.ToArray();
			double height = 490 + (ids.Length * 60);
			if (height > _maxHeight) height = _maxHeight;
			this.Height = height;
			IdentityMenu.SetHeight(this.Height-160);
			bool isActive = false;
			for (int i=0; i<ids.Length; i++) {
				IdentityItem id = new IdentityItem();
				if (ids[i].IsEnabled) {
					isActive = true;
					SetNotifyIcon("green");
					ConnectButton.Visibility = Visibility.Collapsed;
					DisconnectButton.Visibility = Visibility.Visible;
				}
				id.OnStatusChanged += Id_OnStatusChanged;
				id.Identity = ids[i];
				IdList.Children.Add(id);
			}
			if (isActive) {
				ConnectButton.Visibility = Visibility.Collapsed;
				DisconnectButton.Visibility = Visibility.Visible;
			} else {
				ConnectButton.Visibility = Visibility.Visible;
				DisconnectButton.Visibility = Visibility.Collapsed;
			}
			IdList.Height = (double)(ids.Length * 64);
			Placement();
		}

		private void Id_OnStatusChanged(bool attached) {
			bool isActive = false;
			for (int i = 0; i < IdList.Children.Count; i++) {
				IdentityItem item = IdList.Children[i] as IdentityItem;
				if (item.ToggleSwitch.Enabled) {
					isActive = true;
					break;
				}
			}
			if (isActive) {
				ConnectButton.Visibility = Visibility.Collapsed;
				DisconnectButton.Visibility = Visibility.Visible;
			} else {
				ConnectButton.Visibility = Visibility.Visible;
				DisconnectButton.Visibility = Visibility.Collapsed;
			}
		}

		private void SetLocation() {
			var desktopWorkingArea = System.Windows.SystemParameters.WorkArea;


			var height = MainView.ActualHeight;
			IdentityMenu.MainHeight = MainView.ActualHeight;

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
				Arrow.SetValue(Canvas.LeftProperty, this.Width- 30);
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
			var desktopWorkingArea = System.Windows.SystemParameters.WorkArea;
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

		private void AddIdentity(object sender, MouseButtonEventArgs e) {
			UIModel.HideOnLostFocus = false;
			Microsoft.Win32.OpenFileDialog jwtDialog = new Microsoft.Win32.OpenFileDialog();
			UIModel.HideOnLostFocus = true;
			jwtDialog.DefaultExt = ".jwt";
			jwtDialog.Filter = "Ziti Identities (*.jwt)|*.jwt";
			if (jwtDialog.ShowDialog() == true) {
				ShowLoad();
				string fileContent = File.ReadAllText(jwtDialog.FileName);
				
				try {
					Identity createdId = serviceClient.AddIdentity(System.IO.Path.GetFileName(jwtDialog.FileName), false, fileContent);
					ServiceClient.Client client = (ServiceClient.Client)Application.Current.Properties["ServiceClient"];

					client.IdentityOnOff(createdId.FingerPrint, true);
					if (createdId != null) {
						identities.Add(ZitiIdentity.FromClient(createdId));
						LoadIdentities(true);
					} else {
						ShowError("Identity Error", "Identity Id was null, please try again");
					}
				} catch (ServiceException se) {
					ShowError("Error Occurred", se.Message+" "+se.AdditionalInfo);
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
			var hoursString = (hours>9)?hours.ToString():"0"+hours;
			var minutesString = (minutes>9)? minutes.ToString():"0"+minutes;
			var secondsString = (seconds>9) ? seconds.ToString() : "0"+seconds;
			ConnectedTime.Content = hoursString+":"+minutesString+":"+secondsString;
		}

		private void InitializeTimer(int millisAgoStarted) {
			_startDate = DateTime.Now.Subtract(new TimeSpan(0,0,0,0, millisAgoStarted));
			_timer = new System.Windows.Forms.Timer();
			_timer.Interval = 100;
			_timer.Tick += OnTimedEvent;
			_timer.Enabled = true;
			_timer.Start();
		}
		private void Connect(object sender, RoutedEventArgs e) {
			if (!_isServiceInError) {
				ShowLoad();
				this.Dispatcher.Invoke(() => {
					//Dispatcher.Invoke(new Action(() => { }), System.Windows.Threading.DispatcherPriority.ContextIdle);
					DoConnect();
					HideLoad();
				});
			}
		}

		private void DoConnect() {
			try {
				serviceClient.SetTunnelState(true);
				SetNotifyIcon("green");
				ConnectButton.Visibility = Visibility.Collapsed;
				DisconnectButton.Visibility = Visibility.Visible;

				for (int i = 0; i < identities.Count; i++) {
					serviceClient.IdentityOnOff(identities[i].Fingerprint, true);
				}
				for (int i = 0; i < IdList.Children.Count; i++) {
					IdentityItem item = IdList.Children[i] as IdentityItem;
					item._identity.IsEnabled = true;
					item.RefreshUI();
				}
			} catch (ServiceException se) {
				ShowError("Error Occurred", se.Message+" "+se.AdditionalInfo);
			} catch (Exception ex) {
				ShowError("Unexpected Error", "Code 3:" + ex.Message);
			}
		}
		private void Disconnect(object sender, RoutedEventArgs e) {
			if (!_isServiceInError) {
				ShowLoad();
				try {
					ConnectedTime.Content = "00:00:00";
					_timer.Stop();
					serviceClient.SetTunnelState(false);
					SetNotifyIcon("white");
					ConnectButton.Visibility = Visibility.Visible;
					DisconnectButton.Visibility = Visibility.Collapsed;
					for (int i = 0; i < identities.Count; i++) {
						serviceClient.IdentityOnOff(identities[i].Fingerprint, false);
					}
					for (int i = 0; i < IdList.Children.Count; i++) {
						IdentityItem item = IdList.Children[i] as IdentityItem;
						item._identity.IsEnabled = false;
						item.RefreshUI();
					}
				} catch (ServiceException se) {
					ShowError(se.AdditionalInfo, se.Message);
				} catch (Exception ex) {
					ShowError("Unexpected Error", "Code 4:" + ex.Message);
				}
				HideLoad();
			}
		}

		private void ShowLoad() {
			LoadProgress.IsIndeterminate = true;
			LoadingScreen.Visibility = Visibility.Visible;
			((MainWindow)System.Windows.Application.Current.MainWindow).UpdateLayout();
		}

		private void HideLoad() {
			LoadingScreen.Visibility = Visibility.Collapsed;
			LoadProgress.IsIndeterminate = false;
		}

		private void FormFadeOut_Completed(object sender, EventArgs e) {
			closeCompleted = true;
			//this.Close();
		}
		private bool closeCompleted = false;
		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e) {
			if (!closeCompleted) {
				FormFadeOut.Begin();
				e.Cancel = true;
			}
		}

		private void ShowError(String title, String message) {
			ErrorTitle.Content = title;
			ErrorDetails.Text = message;
			ErrorView.Visibility = Visibility.Visible;
		}

		private void CloseError(object sender, RoutedEventArgs e) {
			ErrorView.Visibility = Visibility.Collapsed;
			NoServiceView.Visibility = Visibility.Collapsed;
		}

		private void CloseApp(object sender, RoutedEventArgs e) {
			Application.Current.Shutdown();
		}

		private void MainUI_Deactivated(object sender, EventArgs e) {
			if (this._isAttached) {
#if DEBUG
				Debug.WriteLine("debug is enabled - windows pinned");
#else
				this.Visibility = Visibility.Collapsed;
#endif
			}
		}

		private void Label_MouseDoubleClick(object sender, MouseButtonEventArgs e) {
			Placement();
		}

        private void Button_Click(object sender, RoutedEventArgs e)
        {
			serviceClient.SetLogLevel(NextLevel());
		}

		int cur = 0;
		LogLevelEnum[] levels = new LogLevelEnum[] { LogLevelEnum.FATAL, LogLevelEnum.ERROR, LogLevelEnum.WARN, LogLevelEnum.INFO, LogLevelEnum.DEBUG, LogLevelEnum.TRACE, LogLevelEnum.VERBOSE };
		public LogLevelEnum NextLevel()
		{
			cur++;
			if (cur > 6)
			{
				cur = 0;
			}
			return levels[cur];
		}

		private void IdList_LayoutUpdated(object sender, EventArgs e) {
			Placement();
		}
	}
}
