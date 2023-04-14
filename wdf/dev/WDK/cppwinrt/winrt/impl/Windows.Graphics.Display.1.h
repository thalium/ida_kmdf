// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Graphics.Display.0.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Display {

struct WINRT_EBO IAdvancedColorInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAdvancedColorInfo>
{
    IAdvancedColorInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBrightnessOverride :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBrightnessOverride>
{
    IBrightnessOverride(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBrightnessOverrideSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBrightnessOverrideSettings>
{
    IBrightnessOverrideSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBrightnessOverrideSettingsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBrightnessOverrideSettingsStatics>
{
    IBrightnessOverrideSettingsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBrightnessOverrideStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBrightnessOverrideStatics>
{
    IBrightnessOverrideStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColorOverrideSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorOverrideSettings>
{
    IColorOverrideSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColorOverrideSettingsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorOverrideSettingsStatics>
{
    IColorOverrideSettingsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayEnhancementOverride :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayEnhancementOverride>
{
    IDisplayEnhancementOverride(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayEnhancementOverrideCapabilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayEnhancementOverrideCapabilities>
{
    IDisplayEnhancementOverrideCapabilities(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayEnhancementOverrideCapabilitiesChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayEnhancementOverrideCapabilitiesChangedEventArgs>
{
    IDisplayEnhancementOverrideCapabilitiesChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayEnhancementOverrideStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayEnhancementOverrideStatics>
{
    IDisplayEnhancementOverrideStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayInformation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayInformation>
{
    IDisplayInformation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayInformation2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayInformation2>,
    impl::require<IDisplayInformation2, Windows::Graphics::Display::IDisplayInformation>
{
    IDisplayInformation2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayInformation3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayInformation3>
{
    IDisplayInformation3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayInformation4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayInformation4>
{
    IDisplayInformation4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayInformation5 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayInformation5>
{
    IDisplayInformation5(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayInformationStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayInformationStatics>
{
    IDisplayInformationStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayPropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayPropertiesStatics>
{
    IDisplayPropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

}
