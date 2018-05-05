﻿// This code is distributed under MIT license. 
// Copyright (c) 2015 George Mamaladze
// See license.txt or http://opensource.org/licenses/mit-license.php

using System;

namespace xClient.Core.MouseKeyHook.WinApi
{
    /// <summary>
    ///     The CallWndProc hook procedure is an application-defined or library-defined callback
    ///     function used with the SetWindowsHookEx function. The HOOKPROC type defines a pointer
    ///     to this callback function. CallWndProc is a placeholder for the application-defined
    ///     or library-defined function name.
    /// </summary>
    /// <param name="nCode">
    ///     [in] Specifies whether the hook procedure must process the message.
    ///     If nCode is HC_ACTION, the hook procedure must process the message.
    ///     If nCode is less than zero, the hook procedure must pass the message to the
    ///     CallNextHookEx function without further processing and must return the
    ///     value returned by CallNextHookEx.
    /// </param>
    /// <param name="wParam">
    ///     [in] Specifies whether the message was sent by the current thread.
    ///     If the message was sent by the current thread, it is nonzero; otherwise, it is zero.
    /// </param>
    /// <param name="lParam">
    ///     [in] Pointer to a CWPSTRUCT structure that contains details about the message.
    /// </param>
    /// <returns>
    ///     If nCode is less than zero, the hook procedure must return the value returned by CallNextHookEx.
    ///     If nCode is greater than or equal to zero, it is highly recommended that you call CallNextHookEx
    ///     and return the value it returns; otherwise, other applications that have installed WH_CALLWNDPROC
    ///     hooks will not receive hook notifications and may behave incorrectly as a result. If the hook
    ///     procedure does not call CallNextHookEx, the return value should be zero.
    /// </returns>
    /// <remarks>
    ///     http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winui/winui/windowsuserinterface/windowing/hooks/hookreference/hookfunctions/callwndproc.asp
    /// </remarks>
    public delegate IntPtr HookProcedure(int nCode, IntPtr wParam, IntPtr lParam);
}