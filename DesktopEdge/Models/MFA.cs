using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZitiDesktopEdge.Models {
	public class MFA {
		public string Url { get; set; }
		public string[] RecoveryCodes { get; set; }
		public bool IsAuthenticated { get; set; }
	}
}
