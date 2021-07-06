using System;
using System.IO;

using NLog;

namespace ZitiUpdateService.Checkers {

    public struct ZDEInstallerInfo {
        public DateTime CreationTime;
        public Version Version;
        public bool IsCritical;
        public double TimeRemaining;
        public DateTime InstallTime;
    }

    abstract class UpdateCheck {
        public abstract void IsUpdateAvailable(Version current, out int avail, out string publishedDate);
        public abstract string FileName();
        public abstract void CopyUpdatePackage(string destinationFolder, string destinationName);
        public abstract bool AlreadyDownloaded(string destinationFolder, string destinationName);
        public abstract bool HashIsValid(string destinationFolder, string destinationName);
        public abstract Version GetNextVersion();
        public abstract ZDEInstallerInfo GetZDEInstallerInfo(string fileDestination);
    }
}
