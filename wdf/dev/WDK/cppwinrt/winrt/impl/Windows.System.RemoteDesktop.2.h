// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.RemoteDesktop.1.h"

WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop {

struct InteractiveSession
{
    InteractiveSession() = delete;
    static bool IsRemote();
};

}
