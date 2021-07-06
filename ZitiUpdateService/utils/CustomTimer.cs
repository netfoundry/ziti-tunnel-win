using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.ServiceProcess;
using NLog;

namespace ZitiUpdateService.Utils {
    class CustomTimer : IDisposable {
        private readonly TimerCallback _realCallback;
        private readonly Timer _timer;
        private TimeSpan _period;
        private DateTime _next;
        private DateTime _lastTickTime;
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public CustomTimer(TimerCallback callback, object state, TimeSpan dueTime, TimeSpan period) {
            _timer = new Timer(Callback, state, dueTime, period);
            _realCallback = callback;
            _period = period;
            _next = DateTime.Now.Add(dueTime);
            _lastTickTime = DateTime.Now;
        }

        private void Callback(object state) {
            _next = DateTime.Now.Add(_period);
            _realCallback(state);
        }

        public TimeSpan Period => _period;
        public DateTime Next => _next;
        public TimeSpan DueTime => _next - DateTime.Now;
        public bool Change(TimeSpan dueTime, TimeSpan period) {
            _period = period;
            _next = DateTime.Now.Add(dueTime);
            return _timer.Change(dueTime, period);
        }

        public void Dispose() => _timer.Dispose();

        // update the timer after a system sleep
        public void UpdateTimer(PowerBroadcastStatus e) {
            if (PowerBroadcastStatus.ResumeAutomatic.Equals(e) || PowerBroadcastStatus.ResumeSuspend.Equals(e) || PowerBroadcastStatus.ResumeCritical.Equals(e)) {
                Logger.Info("Installation timer - system resumed");
                Logger.Info("Installation timer - due time : {0}, installation time : {1}", (_next - _lastTickTime), _next);
                TimeSpan sleepTime = DateTime.Now - _lastTickTime;
                DateTime newNextDate = _next.Add(sleepTime);
                TimeSpan newDueTime = newNextDate - DateTime.Now;
                bool status = this.Change(newDueTime, _period);
                if (status) {
                    Logger.Info("Installation timer changed - due time : {0}, installation time : {1}", newDueTime, newNextDate);
                }
                _lastTickTime = DateTime.Now;
            }
            if (PowerBroadcastStatus.Suspend.Equals(e)) {
                Logger.Info("Installation timer - system suspend");
                _lastTickTime = DateTime.Now;
            }
        }

    }

    class TimerState {
        public CustomTimer _timer;
        public Checkers.ZDEInstallerInfo zdeInstallerInfo;
    }
}
