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
    public partial class MenuEditToggle: UserControl {

		public delegate void OnToggle(bool isOn);
		public event OnToggle Toggle;
		public delegate void OnAuthenticate();
		public event OnAuthenticate Authenticate;
		public delegate void OnRecovery();
		public event OnRecovery Recovery;
		private ZitiIdentity _identity;

		private string _label = "";

		public string Label {
			get {
				return _label;
			}
			set {
				this._label = value;
				this.MainLabel.Text = this._label;
			}
		}
		public bool IsOn {
			get {
				return ToggleField.Enabled; 
			}
			set {
				ToggleField.Enabled = value;
			}
		}

		public ZitiIdentity Identity {
			get {
				return _identity; 
			}
			set {
				_identity = value;
				if (_identity.IsMFAEnabled) {
					RecoveryButton.Visibility = Visibility.Visible;
					if (!_identity.MFAInfo.IsAuthenticated) {
						AuthOff.Visibility = Visibility.Visible;
						AuthOn.Visibility = Visibility.Collapsed;
					} else {
						AuthOff.Visibility = Visibility.Collapsed;
						AuthOn.Visibility = Visibility.Visible; 
					}
				} else {
					RecoveryButton.Visibility = Visibility.Collapsed;
					AuthOff.Visibility = Visibility.Collapsed;
				}
			}
		}

		public MenuEditToggle() {
            InitializeComponent();
        }

		public void Toggled(Boolean isOn) {
			this.ToggleField.Enabled = isOn;
			this.Toggle?.Invoke(isOn);
		}

		private void MFAAuthenticate(object sender, MouseButtonEventArgs e) {
			this.Authenticate?.Invoke();
		}

		private void MFARecovery(object sender, MouseButtonEventArgs e) {
			this.Recovery?.Invoke();
		}
	}
}
