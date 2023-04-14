// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Lights.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Lights {

struct WINRT_EBO ILamp :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILamp>,
    impl::require<ILamp, Windows::Foundation::IClosable>
{
    ILamp(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArray :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArray>
{
    ILampArray(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampArrayStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampArrayStatics>
{
    ILampArrayStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampAvailabilityChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampAvailabilityChangedEventArgs>
{
    ILampAvailabilityChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampInfo>
{
    ILampInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILampStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILampStatics>
{
    ILampStatics(std::nullptr_t = nullptr) noexcept {}
};

}
