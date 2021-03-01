﻿using System;
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
    public partial class ServiceInfo: UserControl {

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
				if (this._info.Warning.Length > 0) {
					WarnIcon.ToolTip = this._info.Warning;
					WarnIcon.Visibility = Visibility.Visible;
					WarningColumn.Width = new GridLength(30);
				}
			} 
		}

		public ServiceInfo() {
            InitializeComponent();
        }

		private void MainEdit_PreviewMouseUp(object sender, MouseButtonEventArgs e) {
			(sender as TextBox).SelectAll();
		}

		private void WarnIcon_MouseUp(object sender, MouseButtonEventArgs e) {
			OnMessage?.Invoke(this._info.Warning);
		}

		private void DetailIcon_MouseUp(object sender, MouseButtonEventArgs e) {
			OnDetails?.Invoke(Info);
		}
	}
}
