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

namespace ZitiDesktopEdge {
    /// <summary>
    /// Interaction logic for MenuItem.xaml
    /// </summary>
    public partial class MenuEditSearch : UserControl {

		public delegate void OnFilter(string filter);
		public event OnFilter Filter;

		private string _label = "";

		public string Label {
			get {
				return _label;
			}
			set {
				this._label = value;
				MainLabel.Text = this._label;
			}
		}
		public string Value {
			get {
				return MainEdit.Text; 
			}
			set {
				MainEdit.Text = value;
			}
		}

		public MenuEditSearch() {
            InitializeComponent();
        }

		private void MainEdit_KeyUp(object sender, KeyEventArgs e) {
			if (MainEdit.Text.Trim().Length>0) {
				ClearButton.Content = "clear";
			} else {
				ClearButton.Content = "search";
			}
			Filter(MainEdit.Text);
		}

		private void Label_MouseUp(object sender, MouseButtonEventArgs e) {
			MainEdit.Text = "";
			ClearButton.Content = "search";
			Filter(MainEdit.Text);
		}

		public void Clear() {
			MainEdit.Text = "";
			ClearButton.Content = "search";
			Filter(MainEdit.Text);
		}
	}
}
