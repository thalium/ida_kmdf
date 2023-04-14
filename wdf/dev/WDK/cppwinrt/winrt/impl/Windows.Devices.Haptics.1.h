// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Haptics.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Haptics {

struct WINRT_EBO IKnownSimpleHapticsControllerWaveformsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownSimpleHapticsControllerWaveformsStatics>
{
    IKnownSimpleHapticsControllerWaveformsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISimpleHapticsController :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISimpleHapticsController>
{
    ISimpleHapticsController(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISimpleHapticsControllerFeedback :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISimpleHapticsControllerFeedback>
{
    ISimpleHapticsControllerFeedback(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVibrationDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVibrationDevice>
{
    IVibrationDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVibrationDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVibrationDeviceStatics>
{
    IVibrationDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

}
