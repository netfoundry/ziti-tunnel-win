using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.ServiceClient;

namespace ZitiDesktopEdge {
	/// <summary>
	/// Interaction logic for MenuItem.xaml
	/// </summary>
	public partial class ServiceInfo : UserControl {
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		private ZitiService _info;

		public delegate void Mesage(string message);
		public event Mesage OnMessage;
		public delegate void Details(ZitiService info);
		public event Details OnDetails;

		public ZitiService Info {
			get {
				return _info;
			}
			set {
				this._info = value;
				MainEdit.ToolTip = this._info.ToString();
				MainEdit.Text = this._info.ToString();
				MainLabel.ToolTip = this._info.Name;
				MainLabel.Text = this._info.Name;
				WarningColumn.Width = new GridLength(0);
				if (this._info.Warning.Length > 0) {
					WarnIcon.ToolTip = this._info.Warning;
					WarnIcon.Visibility = Visibility.Visible;
					WarningColumn.Width = new GridLength(30);
				}
				if (this._info.IsAccessable) {
					// the service is accessible - failing posture checks "probably" should be ignored...
					logger.Debug("Service {0} is marked as accessible. failing posture checks probably do not matter", this._info.Name);
				} else {
					if (this._info.PostureChecks != null && this._info.PostureChecks.Length > 0) {
						List<MessageCount> messages = new List<MessageCount>();
						for (int i = 0; i < this._info.PostureChecks.Length; i++) {
							if (!this._info.PostureChecks[i].IsPassing) {
								messages = AppendMessage(messages, this._info.PostureChecks[i].QueryType);
								WarnIcon.Visibility = Visibility.Visible;
								WarningColumn.Width = new GridLength(30);
							}
						}
						if (messages.Count > 0) {
							string checks = "";
							for (int i = 0; i < messages.Count; i++) {
								checks += ((i > 0) ? ", ":"") + messages[i].Total + " " + messages[i].Message;
							}
							WarnIcon.ToolTip = "Posture Check Failing: " + checks;
						}
					}
				}
			}
		}

		private List<MessageCount> AppendMessage(List<MessageCount> items, string message) {
			bool found = false;
			for (int i=0; i<items.Count; i++) {
				if (items[i].Message == message) {
					items[i].Total++;
					found = true;
				}
			}
			if (!found) {
				MessageCount count = new MessageCount();
				count.Total = 1;
				count.Message = message;
				items.Add(count);
			}
			return items;
		}

		public ServiceInfo() {
			InitializeComponent();
		}

		private void MainEdit_PreviewMouseUp(object sender, MouseButtonEventArgs e) {
			(sender as TextBox).SelectAll();
		}

		private void WarnIcon_MouseUp(object sender, MouseButtonEventArgs e) {
			OnMessage?.Invoke(WarnIcon.ToolTip.ToString());
		}

		private void DetailIcon_MouseUp(object sender, MouseButtonEventArgs e) {
			OnDetails?.Invoke(Info);
		}
	}
}
