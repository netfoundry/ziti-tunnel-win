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
using System.Windows.Media.Animation;

namespace ZitiDesktopEdge {
    /// <summary>
    /// Interaction logic for Toggler.xaml
    /// </summary>
    public partial class Toggler : UserControl {

		public delegate void Toggled(bool on);
		public event Toggled OnToggled;
		private bool _isEnabled = false;
		public Toggler() {
            InitializeComponent();
        }

		public Boolean Enabled {
			get {
				return _isEnabled;
			}
			set {
				_isEnabled = value;
				if (_isEnabled) {

					ToggleTab.BeginAnimation(Canvas.LeftProperty, new DoubleAnimation(16, TimeSpan.FromSeconds(.3)));
					OnColor.BeginAnimation(Border.OpacityProperty, new DoubleAnimation(1.0, TimeSpan.FromSeconds(.3)));

					// OnColor.Opacity = 1;
					// ToggleTab.SetValue(Canvas.LeftProperty, 11);
					// Canvas.SetLeft(ToggleTab, 16);
					// Storyboard board = LayoutRoot.FindResource("OnAnimate") as Storyboard;
					// board.Begin();
				} else {
					ToggleTab.BeginAnimation(Canvas.LeftProperty, new DoubleAnimation(1, TimeSpan.FromSeconds(.3)));
					OnColor.BeginAnimation(Border.OpacityProperty, new DoubleAnimation(0, TimeSpan.FromSeconds(.3)));
					// OnColor.Opacity = 0;
					// ToggleTab.SetValue(Canvas.LeftProperty, "1");
					// Canvas.SetLeft(ToggleTab, 1);
					//Storyboard board = LayoutRoot.FindResource("OffAnimate") as Storyboard;
					//board.Begin();
				}
			}
		}
		
		private void OnToggle(object sender, RoutedEventArgs e) {
			e.Handled = true;
			Enabled = !Enabled;
			if (OnToggled != null) {
				OnToggled(Enabled);
			}
		}

		private void OnLoad(object sender, RoutedEventArgs e) {
			if (_isEnabled) {

			} else {

			}
		}
	}
}
