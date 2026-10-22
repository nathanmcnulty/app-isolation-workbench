# Windows PowerShell 5.1. Import only: no LSA API runs until a static method is called.
# Closed helper for the Windows built-in autologon DefaultPassword secret on VM106.
# The caller MUST first pin VM UUID 7e686bee-8c05-43c7-9603-a9562ece224c and SYSTEM
# session 0, own the entire temporary autologon lifecycle, and remove the secret
# immediately after real Explorer login (including failure/recovery cleanup).
# This file neither checks machine identity nor changes Winlogon registry fields.
# References:
# https://learn.microsoft.com/en-us/sysinternals/downloads/autologon
# https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsastoreprivatedata
# LSA secrets are recoverable by administrators. Store accepts a managed string;
# its caller owns that string's lifetime. Only the unmanaged copy is zeroed here.
# The in-process lock does not exclude another process changing the same secret.

if ($null -eq ('Aiw.Research.Worker106AutologonSecret' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Aiw.Research
{
    public static class Worker106AutologonSecret
    {
        private const uint PolicyGetPrivateInformation = 0x00000004;
        private const uint PolicyCreateSecret = 0x00000020;
        private const uint ObjectNameNotFound = 0xC0000034;
        private const string SecretName = "DefaultPassword";
        private static readonly object Gate = new object();

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaUnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaObjectAttributes
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint LsaOpenPolicy(IntPtr systemName,
            ref LsaObjectAttributes attributes, uint access, out IntPtr handle);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint LsaStorePrivateData(IntPtr handle,
            ref LsaUnicodeString key, ref LsaUnicodeString data);
        // A null LSA_UNICODE_STRING pointer deletes the secret; an empty string does not.
        [DllImport("advapi32.dll", EntryPoint = "LsaStorePrivateData", ExactSpelling = true)]
        private static extern uint LsaDeletePrivateData(IntPtr handle,
            ref LsaUnicodeString key, IntPtr data);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint LsaRetrievePrivateData(IntPtr handle,
            ref LsaUnicodeString key, out IntPtr data);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint LsaClose(IntPtr handle);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint LsaNtStatusToWinError(uint status);

        private static void Check(uint status, string operation)
        {
            if (status != 0)
                throw new Win32Exception(unchecked((int)LsaNtStatusToWinError(status)),
                    operation + " failed (NTSTATUS 0x" + status.ToString("X8") + ").");
        }

        private static IntPtr Open()
        {
            LsaObjectAttributes attributes = new LsaObjectAttributes();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LsaObjectAttributes));
            IntPtr handle;
            Check(LsaOpenPolicy(IntPtr.Zero, ref attributes,
                PolicyCreateSecret | PolicyGetPrivateInformation, out handle), "LsaOpenPolicy");
            return handle;
        }

        private static LsaUnicodeString Copy(string value)
        {
            // Include the UTF-16 terminator in MaximumLength without overflowing USHORT.
            if (value == null || value.Length > 32766)
                throw new ArgumentException("String must contain at most 32766 UTF-16 code units.");
            LsaUnicodeString result = new LsaUnicodeString();
            result.Length = checked((ushort)(value.Length * 2));
            result.MaximumLength = checked((ushort)(result.Length + 2));
            result.Buffer = Marshal.StringToHGlobalUni(value);
            return result;
        }

        private static void ZeroFree(ref LsaUnicodeString value)
        {
            if (value.Buffer == IntPtr.Zero) return;
            try
            {
                for (int i = 0; i < value.MaximumLength; i++)
                    Marshal.WriteByte(value.Buffer, i, 0);
            }
            finally
            {
                Marshal.FreeHGlobal(value.Buffer);
                value = new LsaUnicodeString();
            }
        }

        private static bool ExistsCore(IntPtr handle, ref LsaUnicodeString key)
        {
            IntPtr data = IntPtr.Zero;
            try
            {
                uint status = LsaRetrievePrivateData(handle, ref key, out data);
                if (status == ObjectNameNotFound) return false;
                Check(status, "LsaRetrievePrivateData");
                // Never marshal, decode, print or otherwise inspect the returned secret.
                if (data == IntPtr.Zero)
                    throw new InvalidOperationException("LSA returned success without a data buffer.");
                return true;
            }
            finally
            {
                if (data != IntPtr.Zero) Check(LsaFreeMemory(data), "LsaFreeMemory");
            }
        }

        public static bool Exists()
        {
            lock (Gate)
            {
                IntPtr handle = Open();
                LsaUnicodeString key = new LsaUnicodeString();
                try
                {
                    key = Copy(SecretName);
                    return ExistsCore(handle, ref key);
                }
                finally
                {
                    ZeroFree(ref key);
                    Check(LsaClose(handle), "LsaClose");
                }
            }
        }

        public static void Store(string password)
        {
            if (String.IsNullOrEmpty(password) || password.Length > 32766 || password.IndexOf('\0') >= 0)
                throw new ArgumentException("A nonempty password of at most 32766 UTF-16 code units without NUL is required.", "password");
            lock (Gate)
            {
                IntPtr handle = Open();
                LsaUnicodeString key = new LsaUnicodeString();
                LsaUnicodeString data = new LsaUnicodeString();
                try
                {
                    key = Copy(SecretName);
                    if (ExistsCore(handle, ref key))
                        throw new InvalidOperationException("DefaultPassword already exists; refusing to replace it.");
                    data = Copy(password);
                    Check(LsaStorePrivateData(handle, ref key, ref data), "LsaStorePrivateData");
                    if (!ExistsCore(handle, ref key))
                        throw new InvalidOperationException("DefaultPassword was absent after storage.");
                }
                finally
                {
                    ZeroFree(ref data);
                    ZeroFree(ref key);
                    Check(LsaClose(handle), "LsaClose");
                }
            }
        }

        public static void Delete()
        {
            lock (Gate)
            {
                IntPtr handle = Open();
                LsaUnicodeString key = new LsaUnicodeString();
                try
                {
                    key = Copy(SecretName);
                    uint status = LsaDeletePrivateData(handle, ref key, IntPtr.Zero);
                    if (status != ObjectNameNotFound) Check(status, "LsaStorePrivateData(delete)");
                    if (ExistsCore(handle, ref key))
                        throw new InvalidOperationException("DefaultPassword still exists after deletion.");
                }
                finally
                {
                    ZeroFree(ref key);
                    Check(LsaClose(handle), "LsaClose");
                }
            }
        }
    }
}
'@
}
