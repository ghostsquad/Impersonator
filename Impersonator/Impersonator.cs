namespace Impersonator {
    using System;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security.Authentication;
    using System.Security.Principal;

    /// <summary>
    /// derived from http://support.microsoft.com/default.aspx?scid=kb;en-us;Q306158
    /// </summary>
    public class Impersonator : IDisposable {
        private const int LOGON32_LOGON_INTERACTIVE = 2;

        private const int LOGON32_PROVIDER_DEFAULT = 0;

        public WindowsImpersonationContext ImpersonationContext { get; private set; }

        public Impersonator(string userName, string domain, string password) {
            if (!this.ImpersonateValidUser(userName, domain, password)) {
                throw new InvalidCredentialException(
                    string.Format("unable to impersonate {0} in {1} domain", userName, domain));
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DuplicateToken(IntPtr hToken, int impersonationLevel, ref IntPtr hNewToken);

        [DllImport("advapi32.dll")]
        public static extern int LogonUserA(
            string lpszUserName,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();

        public void Dispose() {
            if (this.ImpersonationContext != null) {
                this.ImpersonationContext.Undo();
            }
        }

        private bool ImpersonateValidUser(string userName, string domain, string password) {
            var token = IntPtr.Zero;
            var tokenDuplicate = IntPtr.Zero;

            try {
                if (RevertToSelf()) {
                    if (LogonUserA(
                        userName,
                        domain,
                        password,
                        LOGON32_LOGON_INTERACTIVE,
                        LOGON32_PROVIDER_DEFAULT,
                        ref token) != 0) {
                        if (DuplicateToken(token, 2, ref tokenDuplicate) != 0) {
                            var tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                            this.ImpersonationContext = tempWindowsIdentity.Impersonate();
                        } else {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    } else {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                } else {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } catch (Exception ex) {
                throw new InvalidOperationException(
                    string.Format(
                        @"Error occured while impersonating User '{0}\{1}': {2}",
                        domain,
                        userName,
                        ex.Message),
                    ex);
            } finally {
                if (this.ImpersonationContext != null) {
                    CloseHandle(token);
                    CloseHandle(tokenDuplicate);
                }

                if (token != IntPtr.Zero) {
                    CloseHandle(token);
                }

                if (tokenDuplicate != IntPtr.Zero) {
                    CloseHandle(tokenDuplicate);
                }
            }

            return true;
        }
    }
}