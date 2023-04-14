// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.WindowManagement.1.h"
#include "winrt/impl/Windows.UI.WindowManagement.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement::Preview {

struct WINRT_EBO WindowManagementPreview :
    Windows::UI::WindowManagement::Preview::IWindowManagementPreview
{
    WindowManagementPreview(std::nullptr_t) noexcept {}
    static void SetPreferredMinSize(Windows::UI::WindowManagement::AppWindow const& window, Windows::Foundation::Size const& preferredFrameMinSize);
};

}
