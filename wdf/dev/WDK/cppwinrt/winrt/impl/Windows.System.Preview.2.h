// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Sensors.1.h"
#include "winrt/impl/Windows.System.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Preview {

struct WINRT_EBO TwoPanelHingedDevicePosturePreview :
    Windows::System::Preview::ITwoPanelHingedDevicePosturePreview
{
    TwoPanelHingedDevicePosturePreview(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::System::Preview::TwoPanelHingedDevicePosturePreview> GetDefaultAsync();
};

struct WINRT_EBO TwoPanelHingedDevicePosturePreviewReading :
    Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading
{
    TwoPanelHingedDevicePosturePreviewReading(std::nullptr_t) noexcept {}
};

struct WINRT_EBO TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs :
    Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs
{
    TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs(std::nullptr_t) noexcept {}
};

}
