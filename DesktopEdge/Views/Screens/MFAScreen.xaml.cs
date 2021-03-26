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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Windows.Media.Animation;
using ZitiDesktopEdge.Models;
using ZitiDesktopEdge.ServiceClient;
using ZitiDesktopEdge.DataStructures;

using NLog;
using QRCoder;
using System.Text.RegularExpressions;

namespace ZitiDesktopEdge {
	/// <summary>
	/// Interaction logic for MFA.xaml
	/// </summary>
	public partial class MFAScreen : UserControl {
		private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

		public delegate void CloseAction(bool isComplete);
		public event CloseAction OnClose;
		private string _url = "";
		public delegate void ErrorOccurred(string message);
		public event ErrorOccurred OnError;
		private string[] _codes = new string[0];
		private ZitiIdentity _identity;
		private bool _executing = false;
		public int Type { get; set; }

		public ZitiIdentity Identity { 
			get {
				return this._identity;
			}
			set {
				this._identity = value;
			}
		}

		public MFAScreen() {
			InitializeComponent();
		}

		private void ExecuteClose(object sender, MouseButtonEventArgs e) {
			this.OnClose?.Invoke(false);
		}

		private void ShowError(string message) {
			this.OnError?.Invoke(message);
		}

		private BitmapImage CreateQRFromUrl(string url) {
			QRCodeGenerator qrGenerator = new QRCodeGenerator();
			QRCodeData qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
			QRCode qrCode = new QRCode(qrCodeData);
			System.Drawing.Bitmap qrCodeImage = qrCode.GetGraphic(20);

			MemoryStream ms = new MemoryStream();
			((System.Drawing.Bitmap)qrCodeImage).Save(ms, System.Drawing.Imaging.ImageFormat.Bmp);
			BitmapImage image = new BitmapImage();
			image.BeginInit();
			ms.Seek(0, SeekOrigin.Begin);
			image.StreamSource = ms;
			image.EndInit();
			return image;
		}

		public void ShowSetup(ZitiIdentity identity, string url, string secret) {
			SetupCode.Text = "";
			this._identity = identity;
			MFAImage.Visibility = Visibility.Visible;
			SecretCode.Visibility = Visibility.Collapsed;
			SecretButton.Content = "Show Secret";
			IdName.Content = identity.Name;
			Logger.Debug($"MFA Url: {url}");
			
			MFAImage.Source = CreateQRFromUrl(url);
			SecretCode.Text = secret;

			_url = url;
			MFAArea.Height = 515;
			MFAAuthArea.Visibility = Visibility.Collapsed;
			MFASetupArea.Visibility = Visibility.Visible;
			MFARecoveryArea.Visibility = Visibility.Collapsed;
			SeperationColor.Visibility = Visibility.Visible;
			SetupCode.Focus();
		}

		public void ShowRecovery(string[] codes, ZitiIdentity identity) {
			this._identity = identity;
			MFASetupArea.Visibility = Visibility.Collapsed;
			MFAAuthArea.Visibility = Visibility.Collapsed;
			SeperationColor.Visibility = Visibility.Collapsed;
			MFARecoveryArea.Visibility = Visibility.Visible;
			RecoveryList.Children.Clear();
			_codes = codes;
			MFAArea.Height = 380;
			for (int i=0; i<codes.Length; i++) {
				TextBox label = new TextBox();
				label.Text = codes[i];
				label.BorderThickness = new Thickness(0);
				label.Background = new SolidColorBrush();
				label.Background.Opacity = 0;
				label.HorizontalAlignment = HorizontalAlignment.Center;
				label.HorizontalContentAlignment = HorizontalAlignment.Center;
				label.VerticalAlignment = VerticalAlignment.Center;
				label.VerticalContentAlignment = VerticalAlignment.Center;
				RecoveryList.Children.Add(label);
			}
		}

		public void ShowMFA(ZitiIdentity identity, int type) {
			this.Type = type;
			AuthCode.Text = "";
			this._identity = identity;
			MFASetupArea.Visibility = Visibility.Collapsed;
			MFARecoveryArea.Visibility = Visibility.Collapsed;
			SeperationColor.Visibility = Visibility.Collapsed;
			MFAAuthArea.Visibility = Visibility.Visible;
			MFAArea.Height = 220;
			AuthCode.Focus();
		}

		private BitmapImage LoadImage(string url) {
			var imgUrl = new Uri(url);
			var imageData = new WebClient().DownloadData(imgUrl);
			var bitmapImage = new BitmapImage { CacheOption = BitmapCacheOption.OnLoad };
			bitmapImage.BeginInit();
			bitmapImage.StreamSource = new MemoryStream(imageData);
			bitmapImage.EndInit();
			return bitmapImage;
		}

		private void GoTo(object sender, MouseButtonEventArgs e) {
			if (_url!=null&&_url.Length>0) {
				Process.Start(new ProcessStartInfo(_url) { UseShellExecute = true });
			} else {
				this.OnError?.Invoke("Invalid MFA Url");
			}
		}

		private void ToggleRecovery(object sender, MouseButtonEventArgs e) {
			AuthCode.Text = "";
			if (AuthCode.MaxLength==6) {
				GenerateMFACodes(null, null);
				AuthCode.MaxLength = 8;
				ToggleType.Content = "Use Auth Code";
				AuthSubTitle.Content = "Enter a recovery code";
				AuthCode.Focus();
			} else {
				AuthCode.MaxLength = 6;
				ToggleType.Content = "Use Recovery Code";
				AuthSubTitle.Content = "Enter your authorization code";
				AuthCode.Focus();
			}
		}
		async private void ReturnMFACodes(object sender, MouseButtonEventArgs e) {
			DataClient serviceClient = serviceClient = (DataClient)Application.Current.Properties["ServiceClient"];
			string code = AuthCode.Text;
			Logger.Debug("AuthMFA successful.");
			MfaRecoveryCodesResponse getcodes = await serviceClient.ReturnMFACodes(this._identity.Fingerprint, code);
			if (getcodes.Code != 0) {
				Logger.Error("AuthMFA failed. " + getcodes.Message);
			}
			Logger.Error("PAYLOAD: {0}", getcodes.Payload);
		}
		async private void GenerateMFACodes(object sender, MouseButtonEventArgs e) {
			DataClient serviceClient = serviceClient = (DataClient)Application.Current.Properties["ServiceClient"];
			string code = AuthCode.Text;
			MfaRecoveryCodesResponse gencodes = await serviceClient.GenerateMFACodes(this._identity.Fingerprint, code);
			if (gencodes.Code != 0) {
				Logger.Error("AuthMFA failed. " + gencodes.Message);
			}
			Logger.Error("PAYLOAD: {0}", gencodes.Payload);
		}

		private void SaveCodes() {
			string fileText = string.Join("\n", _codes);
			string name = Regex.Replace(this._identity.Name, "[^a-zA-Z0-9]", String.Empty);

			System.Windows.Forms.SaveFileDialog dialog = new System.Windows.Forms.SaveFileDialog();
			dialog.Filter = "Text Files(*.txt)|*.txt|All(*.*)|*";
			dialog.Title = "Save Recovery Codes";
			dialog.FileName = name+"RecoveryCodes.txt";
			dialog.ShowDialog();

			if (dialog.FileName != "") {
				File.WriteAllText(dialog.FileName, fileText);
			}
		}

		async private void DoSetupAuthenticate() {
			string code = SetupCode.Text;

			DataClient serviceClient = serviceClient = (DataClient)Application.Current.Properties["ServiceClient"];
			SvcResponse resp = await serviceClient.VerifyMFA(this._identity.Fingerprint, code);
			if (resp.Code != 0) {
				this.OnClose?.Invoke(false);
			} else {
				this.OnClose?.Invoke(false);
			}
		}

		async private void DoAuthenticate(object sender, MouseButtonEventArgs e) {
			if (!this._executing) {
				this._executing = true;
				string code = AuthCode.Text;
				if (AuthCode.MaxLength == 8) {
					if (code.Length != 8) this.ShowError("You must enter a valid recovery code");
				} else {
					if (code.Length != 6) this.ShowError("You must enter a valid code");
				}

				DataClient serviceClient = (DataClient)Application.Current.Properties["ServiceClient"];
				if (this.Type == 1) {
					SvcResponse authResult = await serviceClient.AuthMFA(this._identity.Fingerprint, code);
					if (authResult?.Code != 0) {
						Logger.Error("AuthMFA failed. " + authResult.Message);
						this.OnError?.Invoke("Authentication Failed");
						this._executing = false;
					} else {
						MfaRecoveryCodesResponse codeResponse = await serviceClient.ReturnMFACodes(this._identity.Fingerprint, code);
						this._identity.MFAInfo.RecoveryCodes = codeResponse.Payload;
						this._identity.MFAInfo.IsAuthenticated = true;
						this.OnClose?.Invoke(true);
						this._executing = false;
					}
				} else if (this.Type == 2) {
					MfaRecoveryCodesResponse codeResponse = await serviceClient.ReturnMFACodes(this._identity.Fingerprint, code);
					if (codeResponse?.Code != 0) {
						Logger.Error("AuthMFA failed. " + codeResponse.Message);
						AuthCode.Text = "";
						this.OnError?.Invoke("Authentication Failed");
						this._executing = false;
					} else {
						this._identity.MFAInfo.RecoveryCodes = codeResponse.Payload;
						this.OnClose?.Invoke(true);
						this._executing = false;
					}
				} else if (this.Type == 3) {
					SvcResponse authResult = await serviceClient.RemoveMFA(this._identity.Fingerprint, code);
					if (authResult?.Code != 0) {
						Logger.Error("AuthMFA failed. " + authResult.Message);
						AuthCode.Text = "";
						this.OnError?.Invoke("Authentication Failed");
						this._executing = false;
					} else {
						this.OnClose?.Invoke(true);
						this._executing = false;
					}
				} else if (this.Type == 4) {
					MfaRecoveryCodesResponse codeResponse = await serviceClient.GenerateMFACodes(this._identity.Fingerprint, code);
					if (codeResponse?.Code != 0) {
						Logger.Error("AuthMFA failed. " + codeResponse.Message);
						AuthCode.Text = "";
						this.OnError?.Invoke("Authentication Failed");
						this._executing = false;
					} else {
						this._identity.MFAInfo.RecoveryCodes = codeResponse.Payload;
						this.OnClose?.Invoke(true);
						this._executing = false;
					}
				}
			}
		}

		private void RegenerateCodes(object sender, MouseButtonEventArgs e) {
			ShowMFA(this._identity, 4);
		}

		private void ShowSecret(object sender, MouseButtonEventArgs e) {
			if (SecretCode.Visibility==Visibility.Visible) {
				MFAImage.Visibility = Visibility.Visible;
				SecretCode.Visibility = Visibility.Collapsed;
				SecretButton.Content = "Show Secret";
			} else {
				MFAImage.Visibility = Visibility.Collapsed;
				SecretCode.Visibility = Visibility.Visible;
				SecretButton.Content = "Show QR Code";
			}
		}

		private void HandleKey(object sender, KeyEventArgs e) {
			if (e.Key == Key.Return) {
				DoSetupAuthenticate();
			}
		}

		private void AuthCode_KeyUp(object sender, KeyEventArgs e) {
			if (e.Key == Key.Return) {
				DoAuthenticate(sender, null);
			}
		}
	}
}
