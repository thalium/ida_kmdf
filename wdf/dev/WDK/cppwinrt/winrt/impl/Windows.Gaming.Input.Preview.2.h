// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Gaming.Input.Custom.1.h"
#include "winrt/impl/Windows.Gaming.Input.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Preview {

struct GameControllerProviderInfo
{
    GameControllerProviderInfo() = delete;
    static hstring GetParentProviderId(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider);
    static hstring GetProviderId(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider);
};

}
