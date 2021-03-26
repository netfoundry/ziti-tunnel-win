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
using ZitiDesktopEdge.ServiceClient;

namespace Ziti.Desktop.Edge.Views.Screens {
    /// <summary>
    /// Interaction logic for Debugging.xaml
    /// </summary>
    public partial class Debugging : UserControl {

        DataClient client = null;

        public Debugging() {
            InitializeComponent();
        }

        async private void btn1_Click(object sender, RoutedEventArgs e) {
            await client.EnableMFA(FingerPrint.Text);
        }

        async private void btn2_Click(object sender, RoutedEventArgs e) {
            await client.VerifyMFA(FingerPrint.Text, TheMFACode.Text);
        }

        async private void btn3_Click(object sender, RoutedEventArgs e) {
            await client.AuthMFA(FingerPrint.Text, TheMFACode.Text);
        }

        async private void btn4_Click(object sender, RoutedEventArgs e) {
            await client.RemoveMFA(FingerPrint.Text, TheMFACode.Text);
        }

        bool initialized = false;
        private void UserControl_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e) {
            if (!initialized) {
                initialized = true;
                client = (DataClient)Application.Current.Properties["ServiceClient"];
                client.OnMfaEvent += Client_OnMfaEvent;
                client.OnCommunicationError += Client_OnCommunicationError;
            }
        }

        private void Client_OnCommunicationError(object sender, Exception e) {
            MessageBox.Show("debug error: " + e.Message);
        }

        private void Client_OnMfaEvent(object sender, ZitiDesktopEdge.DataStructures.MfaEvent mfa) {
            this.Dispatcher.Invoke(() => {
                MfaActionOp.Text = mfa.Action + " - " + mfa.Op;
                MfaIsVerified.Text = "verified: " + mfa.Successful;
                MfaProvisioningUrl.Text = mfa.ProvisioningUrl;
                if (mfa.RecoveryCodes != null) {
                    MfaRecoveryCodes.Text = string.Join(",", mfa.RecoveryCodes);
                } else {
                    MfaRecoveryCodes.Text = "";
                }
            });
        }

        async private void btn5_Click(object sender, RoutedEventArgs e) {
            await client.ReturnMFACodes(FingerPrint.Text, TheMFACode.Text);
        }

        async private void btn6_Click(object sender, RoutedEventArgs e) {
            await client.GenerateMFACodes(FingerPrint.Text, TheMFACode.Text);
        }
    }
}
