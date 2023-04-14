// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Adc.Provider.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Adc.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Adc {

struct WINRT_EBO IAdcChannel :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdcChannel>,
    impl::require<IAdcChannel, Windows::Foundation::IClosable>
{
    IAdcChannel(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAdcController :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdcController>
{
    IAdcController(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAdcControllerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdcControllerStatics>
{
    IAdcControllerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAdcControllerStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdcControllerStatics2>
{
    IAdcControllerStatics2(std::nullptr_t = nullptr) noexcept {}
};

}
