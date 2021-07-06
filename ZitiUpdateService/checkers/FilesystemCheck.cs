using System;
using System.IO;

using NLog;

namespace ZitiUpdateService.Checkers {
	internal class FilesystemCheck : UpdateCheck {
		private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
		string dest = null;

		int isUpdateAvailable = 1;
		public FilesystemCheck(int updateAvailable) {
			this.isUpdateAvailable = updateAvailable;
		}

		override public bool AlreadyDownloaded(string destinationFolder, string destinationName) {
			return File.Exists(Path.Combine(destinationFolder, destinationName));
		}

		override public void CopyUpdatePackage(string destinationFolder, string destinationName) {
			dest = Path.Combine(destinationFolder, destinationName);
			File.Copy(@"C:\git\github\openziti\desktop-edge-win\Installer\Output\" + FileName(), dest);
		}

		override public string FileName() {
			return "Ziti Desktop Edge Client-1.3.0.exe";
		}

		override public void IsUpdateAvailable(Version current, out int avail, out string publishedDate) {
			avail = isUpdateAvailable;
			publishedDate = File.GetCreationTime(dest).ToString();
		}

		override public bool HashIsValid(string destinationFolder, string destinationName) {
			return true;
		}

		override public Version GetNextVersion() {
			throw new NotImplementedException();
		}

		override public ZDEInstallerInfo GetZDEInstallerInfo(string fileDestination) {
			return new ZDEInstallerInfo() { IsCritical = true, TimeRemaining = 60 };
		}
	}
}
