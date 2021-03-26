using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using ZitiDesktopEdge.DataStructures;

namespace ZitiDesktopEdge.Models {
	public class ZitiService {
		private static readonly Logger logger = LogManager.GetCurrentClassLogger();

		public string Name { get; set; }
		public string[] Protocols { get; set; }
		public Address[] Addresses { get; set; }
		public PortRange[] Ports { get; set; }
		public PostureCheck[] PostureChecks { get; set; }
		public bool OwnsIntercept { get; set; }
		public string AssignedIP { get; set; }

		private bool failingPostureCheck;
		public bool HasFailingPostureCheck() {
			return failingPostureCheck;
		}
		public bool IsAccessable { get; set; }

		public string Warning {
			get {
				if (this.OwnsIntercept) {
					return "";
				} else {
					return "this won't trigger right now"; //$"Another identity already mapped the specified hostname: {Host}.\nThis service is only available via IP";
				}
			}
		}

		public ZitiService() {
		}

		public ZitiService(Service svc) {
			this.Name = svc.Name;
			this.AssignedIP = svc.AssignedIP;
			this.Addresses = svc.Addresses;
			this.Protocols = svc.Protocols == null ? null : svc.Protocols.Select(p => p.ToUpper()).ToArray();
			this.Ports = svc.Ports;
			this.PostureChecks = svc.PostureChecks;
			this.OwnsIntercept = svc.OwnsIntercept;
			if (this.PostureChecks != null) {
				this.failingPostureCheck = this.PostureChecks.Any(p => !p.IsPassing);
			}
			this.IsAccessable = svc.IsAccessable;
			//commented out for now logger.Warn("SERVICE: " + this.Name + " HAS FAILING POSTURE CHECK: " + failingPostureCheck);
		}



		private ServiceMatrix builtMatrix = null;
		public ServiceMatrix Matrix {
			get {
				if (builtMatrix == null) {
					builtMatrix = new ServiceMatrix();
					List<ServiceMatrixElement> matrix = new List<ServiceMatrixElement>(this.Protocols.Length * this.Addresses.Length * this.Ports.Length);

					foreach (var proto in this.Protocols) {
						foreach (var addy in this.Addresses) {
							foreach (var port in this.Ports) {
								ServiceMatrixElement m = new ServiceMatrixElement();
								m.Ports = port.ToString();
								m.Proto = proto.ToUpper();
								m.Address = addy.Hostname;

								matrix.Add(m);
							}
						}
					}
					builtMatrix.Elements = matrix;
				}

				return builtMatrix;
			}
		}

		public override string ToString() {
			string protos = "<none>";
			if (Protocols?.Length > 0) {
				if (Protocols.Length > 1) {
					protos = "[" + string.Join(",", Protocols.Select(p => p.ToString())) + "]";
				} else {
					protos = Protocols[0];
				}
			}
			string addys = "<none>";
			if (Addresses?.Length > 0) {
				if (Addresses.Length > 1) {
					addys = "[" + string.Join(",", Addresses.Select(a => a.ToString()).OrderBy(o => o)) + "]";
				} else {
					addys = Addresses[0].ToString();
				}
			}
			string ranges = "<none>";
			if (Ports?.Length > 0) {
				if (Ports.Length > 1) {
					ranges = "[" + string.Join(",", Ports.Select(a => a.ToString()).OrderBy(o => o)) + "]";
				} else {
					ranges = Ports[0].ToString();
				}
			}

			return protos + ":" + addys + ":" + ranges;
		}
	}

	public class ServiceMatrix {
		public List<ServiceMatrixElement> Elements { get; internal set; }
	}

	public class ServiceMatrixElement {
		public ServiceMatrixElement() {
			Proto = "<none>";
			Address = "<none>";
			Ports = "<none>";
		}

		public string Proto { get; set; }
		public string Address { get; set; }
		public string Ports { get; set; }

		public override string ToString() {
			return Proto + " " + Address + " " + Ports;
		}
	}
}
