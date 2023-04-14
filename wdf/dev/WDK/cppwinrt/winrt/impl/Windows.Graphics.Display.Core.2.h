// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.Display.Core.1.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Display::Core {

struct HdmiDisplayHdr2086Metadata
{
    uint16_t RedPrimaryX;
    uint16_t RedPrimaryY;
    uint16_t GreenPrimaryX;
    uint16_t GreenPrimaryY;
    uint16_t BluePrimaryX;
    uint16_t BluePrimaryY;
    uint16_t WhitePointX;
    uint16_t WhitePointY;
    uint16_t MaxMasteringLuminance;
    uint16_t MinMasteringLuminance;
    uint16_t MaxContentLightLevel;
    uint16_t MaxFrameAverageLightLevel;
};

inline bool operator==(HdmiDisplayHdr2086Metadata const& left, HdmiDisplayHdr2086Metadata const& right) noexcept
{
    return left.RedPrimaryX == right.RedPrimaryX && left.RedPrimaryY == right.RedPrimaryY && left.GreenPrimaryX == right.GreenPrimaryX && left.GreenPrimaryY == right.GreenPrimaryY && left.BluePrimaryX == right.BluePrimaryX && left.BluePrimaryY == right.BluePrimaryY && left.WhitePointX == right.WhitePointX && left.WhitePointY == right.WhitePointY && left.MaxMasteringLuminance == right.MaxMasteringLuminance && left.MinMasteringLuminance == right.MinMasteringLuminance && left.MaxContentLightLevel == right.MaxContentLightLevel && left.MaxFrameAverageLightLevel == right.MaxFrameAverageLightLevel;
}

inline bool operator!=(HdmiDisplayHdr2086Metadata const& left, HdmiDisplayHdr2086Metadata const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Display::Core {

struct WINRT_EBO HdmiDisplayInformation :
    Windows::Graphics::Display::Core::IHdmiDisplayInformation
{
    HdmiDisplayInformation(std::nullptr_t) noexcept {}
    static Windows::Graphics::Display::Core::HdmiDisplayInformation GetForCurrentView();
};

struct WINRT_EBO HdmiDisplayMode :
    Windows::Graphics::Display::Core::IHdmiDisplayMode,
    impl::require<HdmiDisplayMode, Windows::Graphics::Display::Core::IHdmiDisplayMode2>
{
    HdmiDisplayMode(std::nullptr_t) noexcept {}
};

}
