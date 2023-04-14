// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Sensors.0.h"
#include "winrt/impl/Windows.System.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Preview {

struct WINRT_EBO ITwoPanelHingedDevicePosturePreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITwoPanelHingedDevicePosturePreview>
{
    ITwoPanelHingedDevicePosturePreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITwoPanelHingedDevicePosturePreviewReading :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITwoPanelHingedDevicePosturePreviewReading>
{
    ITwoPanelHingedDevicePosturePreviewReading(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs>
{
    ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITwoPanelHingedDevicePosturePreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITwoPanelHingedDevicePosturePreviewStatics>
{
    ITwoPanelHingedDevicePosturePreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

}
