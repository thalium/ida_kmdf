// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Gaming.Input.Custom.0.h"
#include "winrt/impl/Windows.Gaming.Input.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Preview {

struct WINRT_EBO IGameControllerProviderInfoStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGameControllerProviderInfoStatics>
{
    IGameControllerProviderInfoStatics(std::nullptr_t = nullptr) noexcept {}
};

}
