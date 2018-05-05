﻿// This code is distributed under MIT license. 
// Copyright (c) 2015 George Mamaladze
// See license.txt or http://opensource.org/licenses/mit-license.php

using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using xClient.Core.MouseKeyHook.WinApi;

namespace xClient.Core.MouseKeyHook
{
    /// <summary>
    ///     Provides extended data for the MouseClickExt and MouseMoveExt events.
    /// </summary>
    public class MouseEventExtArgs : MouseEventArgs
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="MouseEventExtArgs" /> class.
        /// </summary>
        /// <param name="buttons">One of the MouseButtons values indicating which mouse button was pressed.</param>
        /// <param name="clicks">The number of times a mouse button was pressed.</param>
        /// <param name="point">The x and y -coordinate of a mouse click, in pixels.</param>
        /// <param name="delta">A signed count of the number of detents the wheel has rotated.</param>
        /// <param name="timestamp">The system tick count when the event occurred.</param>
        /// <param name="isMouseKeyDown">True if event signals mouse button down.</param>
        /// <param name="isMouseKeyUp">True if event signals mouse button up.</param>
        internal MouseEventExtArgs(MouseButtons buttons, int clicks, Point point, int delta, int timestamp,
            bool isMouseKeyDown, bool isMouseKeyUp)
            : base(buttons, clicks, point.X, point.Y, delta)
        {
            IsMouseKeyDown = isMouseKeyDown;
            IsMouseKeyUp = isMouseKeyUp;
            Timestamp = timestamp;
        }

        /// <summary>
        ///     Set this property to <b>true</b> inside your event handler to prevent further processing of the event in other
        ///     applications.
        /// </summary>
        public bool Handled { get; set; }

        /// <summary>
        ///     True if event contains information about wheel scroll.
        /// </summary>
        public bool WheelScrolled
        {
            get { return Delta != 0; }
        }

        /// <summary>
        ///     True if event signals a click. False if it was only a move or wheel scroll.
        /// </summary>
        public bool Clicked
        {
            get { return Clicks > 0; }
        }

        /// <summary>
        ///     True if event signals mouse button down.
        /// </summary>
        public bool IsMouseKeyDown { get; private set; }

        /// <summary>
        ///     True if event signals mouse button up.
        /// </summary>
        public bool IsMouseKeyUp { get; private set; }

        /// <summary>
        ///     The system tick count of when the event occurred.
        /// </summary>
        public int Timestamp { get; private set; }

        /// <summary>
        /// </summary>
        internal Point Point
        {
            get { return new Point(X, Y); }
        }

        internal static MouseEventExtArgs FromRawDataApp(CallbackData data)
        {
            var wParam = data.WParam;
            var lParam = data.LParam;

            AppMouseStruct marshalledMouseStruct =
                (AppMouseStruct) Marshal.PtrToStructure(lParam, typeof (AppMouseStruct));
            return FromRawDataUniversal(wParam, marshalledMouseStruct.ToMouseStruct());
        }

        internal static MouseEventExtArgs FromRawDataGlobal(CallbackData data)
        {
            var wParam = data.WParam;
            var lParam = data.LParam;

            MouseStruct marshalledMouseStruct = (MouseStruct) Marshal.PtrToStructure(lParam, typeof (MouseStruct));
            return FromRawDataUniversal(wParam, marshalledMouseStruct);
        }

        /// <summary>
        ///     Creates <see cref="MouseEventExtArgs" /> from relevant mouse data.
        /// </summary>
        /// <param name="wParam">First Windows Message parameter.</param>
        /// <param name="mouseInfo">A MouseStruct containing information from which to construct MouseEventExtArgs.</param>
        /// <returns>A new MouseEventExtArgs object.</returns>
        private static MouseEventExtArgs FromRawDataUniversal(IntPtr wParam, MouseStruct mouseInfo)
        {
            MouseButtons button = MouseButtons.None;
            short mouseDelta = 0;
            int clickCount = 0;

            bool isMouseKeyDown = false;
            bool isMouseKeyUp = false;


            switch ((long) wParam)
            {
                case Messages.WM_LBUTTONDOWN:
                    isMouseKeyDown = true;
                    button = MouseButtons.Left;
                    clickCount = 1;
                    break;
                case Messages.WM_LBUTTONUP:
                    isMouseKeyUp = true;
                    button = MouseButtons.Left;
                    clickCount = 1;
                    break;
                case Messages.WM_LBUTTONDBLCLK:
                    isMouseKeyDown = true;
                    button = MouseButtons.Left;
                    clickCount = 2;
                    break;
                case Messages.WM_RBUTTONDOWN:
                    isMouseKeyDown = true;
                    button = MouseButtons.Right;
                    clickCount = 1;
                    break;
                case Messages.WM_RBUTTONUP:
                    isMouseKeyUp = true;
                    button = MouseButtons.Right;
                    clickCount = 1;
                    break;
                case Messages.WM_RBUTTONDBLCLK:
                    isMouseKeyDown = true;
                    button = MouseButtons.Right;
                    clickCount = 2;
                    break;
                case Messages.WM_MBUTTONDOWN:
                    isMouseKeyDown = true;
                    button = MouseButtons.Middle;
                    clickCount = 1;
                    break;
                case Messages.WM_MBUTTONUP:
                    isMouseKeyUp = true;
                    button = MouseButtons.Middle;
                    clickCount = 1;
                    break;
                case Messages.WM_MBUTTONDBLCLK:
                    isMouseKeyDown = true;
                    button = MouseButtons.Middle;
                    clickCount = 2;
                    break;
                case Messages.WM_MOUSEWHEEL:
                    mouseDelta = mouseInfo.MouseData;
                    break;
                case Messages.WM_XBUTTONDOWN:
                    button = mouseInfo.MouseData == 1
                        ? MouseButtons.XButton1
                        : MouseButtons.XButton2;
                    isMouseKeyDown = true;
                    clickCount = 1;
                    break;

                case Messages.WM_XBUTTONUP:
                    button = mouseInfo.MouseData == 1
                        ? MouseButtons.XButton1
                        : MouseButtons.XButton2;
                    isMouseKeyUp = true;
                    clickCount = 1;
                    break;

                case Messages.WM_XBUTTONDBLCLK:
                    isMouseKeyDown = true;
                    button = mouseInfo.MouseData == 1
                        ? MouseButtons.XButton1
                        : MouseButtons.XButton2;
                    clickCount = 2;
                    break;

                case Messages.WM_MOUSEHWHEEL:
                    mouseDelta = mouseInfo.MouseData;
                    break;
            }

            var e = new MouseEventExtArgs(
                button,
                clickCount,
                mouseInfo.Point,
                mouseDelta,
                mouseInfo.Timestamp,
                isMouseKeyDown,
                isMouseKeyUp);

            return e;
        }

        internal MouseEventExtArgs ToDoubleClickEventArgs()
        {
            return new MouseEventExtArgs(Button, 2, Point, Delta, Timestamp, IsMouseKeyDown, IsMouseKeyUp);
        }
    }
}