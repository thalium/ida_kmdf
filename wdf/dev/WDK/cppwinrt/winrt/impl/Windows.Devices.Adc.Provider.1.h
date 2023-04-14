// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Adc.Provider.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Adc::Provider {

struct WINRT_EBO IAdcControllerProvider :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdcControllerProvider>
{
    IAdcControllerProvider(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAdcProvider :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdcProvider>
{
    IAdcProvider(std::nullptr_t = nullptr) noexcept {}
};

}
