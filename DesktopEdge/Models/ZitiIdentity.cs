using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZitiDesktopEdge.Models {
	public class ZitiIdentity {
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();
		public List<ZitiService> Services { get; set; }
		public string Name { get; set; }
		public string ControllerUrl { get; set; }
		public bool IsEnabled { get; set; }
		public string EnrollmentStatus { get; set; }
		public string Status { get; set; }
		public bool IsMFAEnabled { get; set; }
		public MFA MFAInfo { get; set; }

		private bool svcFailingPostureCheck = false;
		public bool HasServiceFailingPostureCheck {
			get {
				return svcFailingPostureCheck;
			}
			set {
				logger.Info("Identity: {0} posture change. is a posture check failing: {1}", Name, !value);
				svcFailingPostureCheck = value;
			}
		}

		public ZitiIdentity()
		{
			//default constructor to support named initialization
			this.Services = new List<ZitiService>();
		}

		public ZitiIdentity(string Name, string ControllerUrl, bool IsEnabled, List<ZitiService> Services) {
			this.Name = Name;
			this.Services = Services;
			this.ControllerUrl = ControllerUrl;
			this.IsEnabled = IsEnabled;
			this.EnrollmentStatus = "Enrolled";
			this.Status = "Available";
		}

		public string Fingerprint { get; set; }

		public static ZitiIdentity FromClient(DataStructures.Identity id) {
			ZitiIdentity zid = new ZitiIdentity() {
				ControllerUrl = id.Config.ztAPI + " at " + id.ControllerVersion,
				EnrollmentStatus = "status",
				Fingerprint = id.FingerPrint,
				IsEnabled = id.Active,
				Name = (string.IsNullOrEmpty(id.Name) ? id.FingerPrint : id.Name),
				Status = id.Status,
				IsMFAEnabled = id.MfaEnabled,
				MFAInfo = new MFA() { 
					IsAuthenticated = !id.MfaNeeded,
				},
			};

			if (id.Services != null) {
				foreach (var svc in id.Services) {
					if (svc != null) {
						var zsvc = new ZitiService(svc);
						zid.Services.Add(zsvc);
					}
				}
				zid.HasServiceFailingPostureCheck = zid.Services.Any(p => !p.HasFailingPostureCheck());
			}
			return zid;
		}
	}
}
