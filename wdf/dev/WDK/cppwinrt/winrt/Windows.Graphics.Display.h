// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Graphics.Display.2.h"
#include "winrt/Windows.Graphics.h"

namespace winrt::impl {

template <typename D> Windows::Graphics::Display::AdvancedColorKind consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::CurrentAdvancedColorKind() const
{
    Windows::Graphics::Display::AdvancedColorKind value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_CurrentAdvancedColorKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::RedPrimary() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_RedPrimary(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::GreenPrimary() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_GreenPrimary(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::BluePrimary() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_BluePrimary(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::WhitePoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_WhitePoint(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::MaxLuminanceInNits() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_MaxLuminanceInNits(&value));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::MinLuminanceInNits() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_MinLuminanceInNits(&value));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::MaxAverageFullFrameLuminanceInNits() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_MaxAverageFullFrameLuminanceInNits(&value));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::SdrWhiteLevelInNits() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->get_SdrWhiteLevelInNits(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::IsHdrMetadataFormatCurrentlySupported(Windows::Graphics::Display::HdrMetadataFormat const& format) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->IsHdrMetadataFormatCurrentlySupported(get_abi(format), &result));
    return result;
}

template <typename D> bool consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::IsAdvancedColorKindAvailable(Windows::Graphics::Display::AdvancedColorKind const& kind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IAdvancedColorInfo)->IsAdvancedColorKindAvailable(get_abi(kind), &result));
    return result;
}

template <typename D> bool consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->get_IsSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->get_IsOverrideActive(&value));
    return value;
}

template <typename D> double consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevel() const
{
    double level{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->get_BrightnessLevel(&level));
    return level;
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::SetBrightnessLevel(double brightnessLevel, Windows::Graphics::Display::DisplayBrightnessOverrideOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->SetBrightnessLevel(brightnessLevel, get_abi(options)));
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::SetBrightnessScenario(Windows::Graphics::Display::DisplayBrightnessScenario const& scenario, Windows::Graphics::Display::DisplayBrightnessOverrideOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->SetBrightnessScenario(get_abi(scenario), get_abi(options)));
}

template <typename D> double consume_Windows_Graphics_Display_IBrightnessOverride<D>::GetLevelForScenario(Windows::Graphics::Display::DisplayBrightnessScenario const& scenario) const
{
    double brightnessLevel{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->GetLevelForScenario(get_abi(scenario), &brightnessLevel));
    return brightnessLevel;
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::StartOverride() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->StartOverride());
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::StopOverride() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->StopOverride());
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->add_IsSupportedChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged_revoker consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsSupportedChanged_revoker>(this, IsSupportedChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->remove_IsSupportedChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->add_IsOverrideActiveChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged_revoker consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsOverrideActiveChanged_revoker>(this, IsOverrideActiveChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->remove_IsOverrideActiveChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->add_BrightnessLevelChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged_revoker consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, BrightnessLevelChanged_revoker>(this, BrightnessLevelChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverride)->remove_BrightnessLevelChanged(get_abi(token)));
}

template <typename D> double consume_Windows_Graphics_Display_IBrightnessOverrideSettings<D>::DesiredLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideSettings)->get_DesiredLevel(&value));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IBrightnessOverrideSettings<D>::DesiredNits() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideSettings)->get_DesiredNits(&value));
    return value;
}

template <typename D> Windows::Graphics::Display::BrightnessOverrideSettings consume_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics<D>::CreateFromLevel(double level) const
{
    Windows::Graphics::Display::BrightnessOverrideSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideSettingsStatics)->CreateFromLevel(level, put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::BrightnessOverrideSettings consume_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics<D>::CreateFromNits(float nits) const
{
    Windows::Graphics::Display::BrightnessOverrideSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideSettingsStatics)->CreateFromNits(nits, put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::BrightnessOverrideSettings consume_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics<D>::CreateFromDisplayBrightnessOverrideScenario(Windows::Graphics::Display::DisplayBrightnessOverrideScenario const& overrideScenario) const
{
    Windows::Graphics::Display::BrightnessOverrideSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideSettingsStatics)->CreateFromDisplayBrightnessOverrideScenario(get_abi(overrideScenario), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::BrightnessOverride consume_Windows_Graphics_Display_IBrightnessOverrideStatics<D>::GetDefaultForSystem() const
{
    Windows::Graphics::Display::BrightnessOverride value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideStatics)->GetDefaultForSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::BrightnessOverride consume_Windows_Graphics_Display_IBrightnessOverrideStatics<D>::GetForCurrentView() const
{
    Windows::Graphics::Display::BrightnessOverride value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideStatics)->GetForCurrentView(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Display_IBrightnessOverrideStatics<D>::SaveForSystemAsync(Windows::Graphics::Display::BrightnessOverride const& value) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IBrightnessOverrideStatics)->SaveForSystemAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Display::DisplayColorOverrideScenario consume_Windows_Graphics_Display_IColorOverrideSettings<D>::DesiredDisplayColorOverrideScenario() const
{
    Windows::Graphics::Display::DisplayColorOverrideScenario value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IColorOverrideSettings)->get_DesiredDisplayColorOverrideScenario(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::ColorOverrideSettings consume_Windows_Graphics_Display_IColorOverrideSettingsStatics<D>::CreateFromDisplayColorOverrideScenario(Windows::Graphics::Display::DisplayColorOverrideScenario const& overrideScenario) const
{
    Windows::Graphics::Display::ColorOverrideSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IColorOverrideSettingsStatics)->CreateFromDisplayColorOverrideScenario(get_abi(overrideScenario), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::ColorOverrideSettings consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::ColorOverrideSettings() const
{
    Windows::Graphics::Display::ColorOverrideSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->get_ColorOverrideSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::ColorOverrideSettings(Windows::Graphics::Display::ColorOverrideSettings const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->put_ColorOverrideSettings(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::BrightnessOverrideSettings consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::BrightnessOverrideSettings() const
{
    Windows::Graphics::Display::BrightnessOverrideSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->get_BrightnessOverrideSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::BrightnessOverrideSettings(Windows::Graphics::Display::BrightnessOverrideSettings const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->put_BrightnessOverrideSettings(get_abi(value)));
}

template <typename D> bool consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverride() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->get_CanOverride(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->get_IsOverrideActive(&value));
    return value;
}

template <typename D> Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::GetCurrentDisplayEnhancementOverrideCapabilities() const
{
    Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->GetCurrentDisplayEnhancementOverrideCapabilities(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::RequestOverride() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->RequestOverride());
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::StopOverride() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->StopOverride());
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->add_CanOverrideChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged_revoker consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CanOverrideChanged_revoker>(this, CanOverrideChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->remove_CanOverrideChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->add_IsOverrideActiveChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged_revoker consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsOverrideActiveChanged_revoker>(this, IsOverrideActiveChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->remove_IsOverrideActiveChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->add_DisplayEnhancementOverrideCapabilitiesChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged_revoker consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DisplayEnhancementOverrideCapabilitiesChanged_revoker>(this, DisplayEnhancementOverrideCapabilitiesChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverride)->remove_DisplayEnhancementOverrideCapabilitiesChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities<D>::IsBrightnessControlSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities)->get_IsBrightnessControlSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities<D>::IsBrightnessNitsControlSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities)->get_IsBrightnessNitsControlSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::NitRange> consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities<D>::GetSupportedNitRanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::NitRange> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities)->GetSupportedNitRanges(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilitiesChangedEventArgs<D>::Capabilities() const
{
    Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::DisplayEnhancementOverride consume_Windows_Graphics_Display_IDisplayEnhancementOverrideStatics<D>::GetForCurrentView() const
{
    Windows::Graphics::Display::DisplayEnhancementOverride result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayEnhancementOverrideStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Graphics_Display_IDisplayInformation<D>::CurrentOrientation() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_CurrentOrientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Graphics_Display_IDisplayInformation<D>::NativeOrientation() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_NativeOrientation(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->add_OrientationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, OrientationChanged_revoker>(this, OrientationChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->remove_OrientationChanged(get_abi(token)));
}

template <typename D> Windows::Graphics::Display::ResolutionScale consume_Windows_Graphics_Display_IDisplayInformation<D>::ResolutionScale() const
{
    Windows::Graphics::Display::ResolutionScale value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_ResolutionScale(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IDisplayInformation<D>::LogicalDpi() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_LogicalDpi(&value));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IDisplayInformation<D>::RawDpiX() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_RawDpiX(&value));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IDisplayInformation<D>::RawDpiY() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_RawDpiY(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->add_DpiChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DpiChanged_revoker>(this, DpiChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->remove_DpiChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->get_StereoEnabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->add_StereoEnabledChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StereoEnabledChanged_revoker>(this, StereoEnabledChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->remove_StereoEnabledChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Graphics_Display_IDisplayInformation<D>::GetColorProfileAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->GetColorProfileAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->add_ColorProfileChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ColorProfileChanged_revoker>(this, ColorProfileChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation)->remove_ColorProfileChanged(get_abi(token)));
}

template <typename D> double consume_Windows_Graphics_Display_IDisplayInformation2<D>::RawPixelsPerViewPixel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation2)->get_RawPixelsPerViewPixel(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Graphics_Display_IDisplayInformation3<D>::DiagonalSizeInInches() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation3)->get_DiagonalSizeInInches(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Display_IDisplayInformation4<D>::ScreenWidthInRawPixels() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation4)->get_ScreenWidthInRawPixels(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Display_IDisplayInformation4<D>::ScreenHeightInRawPixels() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation4)->get_ScreenHeightInRawPixels(&value));
    return value;
}

template <typename D> Windows::Graphics::Display::AdvancedColorInfo consume_Windows_Graphics_Display_IDisplayInformation5<D>::GetAdvancedColorInfo() const
{
    Windows::Graphics::Display::AdvancedColorInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation5)->GetAdvancedColorInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation5)->add_AdvancedColorInfoChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AdvancedColorInfoChanged_revoker>(this, AdvancedColorInfoChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayInformation5)->remove_AdvancedColorInfoChanged(get_abi(token)));
}

template <typename D> Windows::Graphics::Display::DisplayInformation consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::GetForCurrentView() const
{
    Windows::Graphics::Display::DisplayInformation current{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformationStatics)->GetForCurrentView(put_abi(current)));
    return current;
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::AutoRotationPreferences() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformationStatics)->get_AutoRotationPreferences(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformationStatics)->put_AutoRotationPreferences(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayInformationStatics)->add_DisplayContentsInvalidated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated_revoker consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DisplayContentsInvalidated_revoker>(this, DisplayContentsInvalidated(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayInformationStatics)->remove_DisplayContentsInvalidated(get_abi(token)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::CurrentOrientation() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->get_CurrentOrientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::NativeOrientation() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->get_NativeOrientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::AutoRotationPreferences() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->get_AutoRotationPreferences(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->put_AutoRotationPreferences(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->add_OrientationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    return impl::make_event_revoker<D, OrientationChanged_revoker>(this, OrientationChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_OrientationChanged(get_abi(token)));
}

template <typename D> Windows::Graphics::Display::ResolutionScale consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ResolutionScale() const
{
    Windows::Graphics::Display::ResolutionScale value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->get_ResolutionScale(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpi() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->get_LogicalDpi(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->add_LogicalDpiChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LogicalDpiChanged_revoker>(this, LogicalDpiChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_LogicalDpiChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->get_StereoEnabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->add_StereoEnabledChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    return impl::make_event_revoker<D, StereoEnabledChanged_revoker>(this, StereoEnabledChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_StereoEnabledChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::GetColorProfileAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->GetColorProfileAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->add_ColorProfileChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ColorProfileChanged_revoker>(this, ColorProfileChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_ColorProfileChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->add_DisplayContentsInvalidated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DisplayContentsInvalidated_revoker>(this, DisplayContentsInvalidated(handler));
}

template <typename D> void consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_DisplayContentsInvalidated(get_abi(token)));
}

template <> struct delegate<Windows::Graphics::Display::DisplayPropertiesEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Graphics::Display::DisplayPropertiesEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Graphics::Display::DisplayPropertiesEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IAdvancedColorInfo> : produce_base<D, Windows::Graphics::Display::IAdvancedColorInfo>
{
    int32_t WINRT_CALL get_CurrentAdvancedColorKind(Windows::Graphics::Display::AdvancedColorKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentAdvancedColorKind, WINRT_WRAP(Windows::Graphics::Display::AdvancedColorKind));
            *value = detach_from<Windows::Graphics::Display::AdvancedColorKind>(this->shim().CurrentAdvancedColorKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedPrimary(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedPrimary, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().RedPrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GreenPrimary(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GreenPrimary, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().GreenPrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BluePrimary(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluePrimary, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().BluePrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WhitePoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WhitePoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().WhitePoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxLuminanceInNits(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxLuminanceInNits, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxLuminanceInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinLuminanceInNits(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinLuminanceInNits, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinLuminanceInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAverageFullFrameLuminanceInNits(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAverageFullFrameLuminanceInNits, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxAverageFullFrameLuminanceInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SdrWhiteLevelInNits(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SdrWhiteLevelInNits, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().SdrWhiteLevelInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsHdrMetadataFormatCurrentlySupported(Windows::Graphics::Display::HdrMetadataFormat format, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHdrMetadataFormatCurrentlySupported, WINRT_WRAP(bool), Windows::Graphics::Display::HdrMetadataFormat const&);
            *result = detach_from<bool>(this->shim().IsHdrMetadataFormatCurrentlySupported(*reinterpret_cast<Windows::Graphics::Display::HdrMetadataFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsAdvancedColorKindAvailable(Windows::Graphics::Display::AdvancedColorKind kind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAdvancedColorKindAvailable, WINRT_WRAP(bool), Windows::Graphics::Display::AdvancedColorKind const&);
            *result = detach_from<bool>(this->shim().IsAdvancedColorKindAvailable(*reinterpret_cast<Windows::Graphics::Display::AdvancedColorKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IBrightnessOverride> : produce_base<D, Windows::Graphics::Display::IBrightnessOverride>
{
    int32_t WINRT_CALL get_IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverrideActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverrideActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOverrideActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrightnessLevel(double* level) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessLevel, WINRT_WRAP(double));
            *level = detach_from<double>(this->shim().BrightnessLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBrightnessLevel(double brightnessLevel, Windows::Graphics::Display::DisplayBrightnessOverrideOptions options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBrightnessLevel, WINRT_WRAP(void), double, Windows::Graphics::Display::DisplayBrightnessOverrideOptions const&);
            this->shim().SetBrightnessLevel(brightnessLevel, *reinterpret_cast<Windows::Graphics::Display::DisplayBrightnessOverrideOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBrightnessScenario(Windows::Graphics::Display::DisplayBrightnessScenario scenario, Windows::Graphics::Display::DisplayBrightnessOverrideOptions options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBrightnessScenario, WINRT_WRAP(void), Windows::Graphics::Display::DisplayBrightnessScenario const&, Windows::Graphics::Display::DisplayBrightnessOverrideOptions const&);
            this->shim().SetBrightnessScenario(*reinterpret_cast<Windows::Graphics::Display::DisplayBrightnessScenario const*>(&scenario), *reinterpret_cast<Windows::Graphics::Display::DisplayBrightnessOverrideOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLevelForScenario(Windows::Graphics::Display::DisplayBrightnessScenario scenario, double* brightnessLevel) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLevelForScenario, WINRT_WRAP(double), Windows::Graphics::Display::DisplayBrightnessScenario const&);
            *brightnessLevel = detach_from<double>(this->shim().GetLevelForScenario(*reinterpret_cast<Windows::Graphics::Display::DisplayBrightnessScenario const*>(&scenario)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartOverride() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartOverride, WINRT_WRAP(void));
            this->shim().StartOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopOverride() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopOverride, WINRT_WRAP(void));
            this->shim().StopOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsSupportedChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupportedChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsSupportedChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsSupportedChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsSupportedChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsSupportedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_IsOverrideActiveChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverrideActiveChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsOverrideActiveChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsOverrideActiveChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsOverrideActiveChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsOverrideActiveChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BrightnessLevelChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessLevelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BrightnessLevelChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::BrightnessOverride, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BrightnessLevelChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BrightnessLevelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BrightnessLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IBrightnessOverrideSettings> : produce_base<D, Windows::Graphics::Display::IBrightnessOverrideSettings>
{
    int32_t WINRT_CALL get_DesiredLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredNits(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredNits, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DesiredNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IBrightnessOverrideSettingsStatics> : produce_base<D, Windows::Graphics::Display::IBrightnessOverrideSettingsStatics>
{
    int32_t WINRT_CALL CreateFromLevel(double level, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLevel, WINRT_WRAP(Windows::Graphics::Display::BrightnessOverrideSettings), double);
            *result = detach_from<Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().CreateFromLevel(level));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNits(float nits, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNits, WINRT_WRAP(Windows::Graphics::Display::BrightnessOverrideSettings), float);
            *result = detach_from<Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().CreateFromNits(nits));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromDisplayBrightnessOverrideScenario(Windows::Graphics::Display::DisplayBrightnessOverrideScenario overrideScenario, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDisplayBrightnessOverrideScenario, WINRT_WRAP(Windows::Graphics::Display::BrightnessOverrideSettings), Windows::Graphics::Display::DisplayBrightnessOverrideScenario const&);
            *result = detach_from<Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().CreateFromDisplayBrightnessOverrideScenario(*reinterpret_cast<Windows::Graphics::Display::DisplayBrightnessOverrideScenario const*>(&overrideScenario)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IBrightnessOverrideStatics> : produce_base<D, Windows::Graphics::Display::IBrightnessOverrideStatics>
{
    int32_t WINRT_CALL GetDefaultForSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultForSystem, WINRT_WRAP(Windows::Graphics::Display::BrightnessOverride));
            *value = detach_from<Windows::Graphics::Display::BrightnessOverride>(this->shim().GetDefaultForSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Graphics::Display::BrightnessOverride));
            *value = detach_from<Windows::Graphics::Display::BrightnessOverride>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveForSystemAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveForSystemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Graphics::Display::BrightnessOverride const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SaveForSystemAsync(*reinterpret_cast<Windows::Graphics::Display::BrightnessOverride const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IColorOverrideSettings> : produce_base<D, Windows::Graphics::Display::IColorOverrideSettings>
{
    int32_t WINRT_CALL get_DesiredDisplayColorOverrideScenario(Windows::Graphics::Display::DisplayColorOverrideScenario* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDisplayColorOverrideScenario, WINRT_WRAP(Windows::Graphics::Display::DisplayColorOverrideScenario));
            *value = detach_from<Windows::Graphics::Display::DisplayColorOverrideScenario>(this->shim().DesiredDisplayColorOverrideScenario());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IColorOverrideSettingsStatics> : produce_base<D, Windows::Graphics::Display::IColorOverrideSettingsStatics>
{
    int32_t WINRT_CALL CreateFromDisplayColorOverrideScenario(Windows::Graphics::Display::DisplayColorOverrideScenario overrideScenario, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDisplayColorOverrideScenario, WINRT_WRAP(Windows::Graphics::Display::ColorOverrideSettings), Windows::Graphics::Display::DisplayColorOverrideScenario const&);
            *result = detach_from<Windows::Graphics::Display::ColorOverrideSettings>(this->shim().CreateFromDisplayColorOverrideScenario(*reinterpret_cast<Windows::Graphics::Display::DisplayColorOverrideScenario const*>(&overrideScenario)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayEnhancementOverride> : produce_base<D, Windows::Graphics::Display::IDisplayEnhancementOverride>
{
    int32_t WINRT_CALL get_ColorOverrideSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorOverrideSettings, WINRT_WRAP(Windows::Graphics::Display::ColorOverrideSettings));
            *value = detach_from<Windows::Graphics::Display::ColorOverrideSettings>(this->shim().ColorOverrideSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ColorOverrideSettings(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorOverrideSettings, WINRT_WRAP(void), Windows::Graphics::Display::ColorOverrideSettings const&);
            this->shim().ColorOverrideSettings(*reinterpret_cast<Windows::Graphics::Display::ColorOverrideSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrightnessOverrideSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessOverrideSettings, WINRT_WRAP(Windows::Graphics::Display::BrightnessOverrideSettings));
            *value = detach_from<Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().BrightnessOverrideSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BrightnessOverrideSettings(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessOverrideSettings, WINRT_WRAP(void), Windows::Graphics::Display::BrightnessOverrideSettings const&);
            this->shim().BrightnessOverrideSettings(*reinterpret_cast<Windows::Graphics::Display::BrightnessOverrideSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanOverride(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanOverride, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverrideActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverrideActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOverrideActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentDisplayEnhancementOverrideCapabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentDisplayEnhancementOverrideCapabilities, WINRT_WRAP(Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities));
            *value = detach_from<Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities>(this->shim().GetCurrentDisplayEnhancementOverrideCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestOverride() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestOverride, WINRT_WRAP(void));
            this->shim().RequestOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopOverride() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopOverride, WINRT_WRAP(void));
            this->shim().StopOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CanOverrideChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanOverrideChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CanOverrideChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CanOverrideChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CanOverrideChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CanOverrideChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_IsOverrideActiveChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverrideActiveChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsOverrideActiveChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsOverrideActiveChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsOverrideActiveChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsOverrideActiveChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DisplayEnhancementOverrideCapabilitiesChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayEnhancementOverrideCapabilitiesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DisplayEnhancementOverrideCapabilitiesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayEnhancementOverride, Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisplayEnhancementOverrideCapabilitiesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisplayEnhancementOverrideCapabilitiesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisplayEnhancementOverrideCapabilitiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities> : produce_base<D, Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities>
{
    int32_t WINRT_CALL get_IsBrightnessControlSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBrightnessControlSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBrightnessControlSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBrightnessNitsControlSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBrightnessNitsControlSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBrightnessNitsControlSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedNitRanges(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedNitRanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::NitRange>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Display::NitRange>>(this->shim().GetSupportedNitRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs> : produce_base<D, Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs>
{
    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities));
            *value = detach_from<Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayEnhancementOverrideStatics> : produce_base<D, Windows::Graphics::Display::IDisplayEnhancementOverrideStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Graphics::Display::DisplayEnhancementOverride));
            *result = detach_from<Windows::Graphics::Display::DisplayEnhancementOverride>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayInformation> : produce_base<D, Windows::Graphics::Display::IDisplayInformation>
{
    int32_t WINRT_CALL get_CurrentOrientation(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentOrientation, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().CurrentOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NativeOrientation(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NativeOrientation, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().NativeOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OrientationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().OrientationChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OrientationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OrientationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OrientationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_ResolutionScale(Windows::Graphics::Display::ResolutionScale* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolutionScale, WINRT_WRAP(Windows::Graphics::Display::ResolutionScale));
            *value = detach_from<Windows::Graphics::Display::ResolutionScale>(this->shim().ResolutionScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogicalDpi(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogicalDpi, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LogicalDpi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawDpiX(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawDpiX, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RawDpiX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawDpiY(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawDpiY, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RawDpiY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DpiChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DpiChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DpiChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DpiChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DpiChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_StereoEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StereoEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StereoEnabledChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StereoEnabledChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StereoEnabledChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StereoEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StereoEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetColorProfileAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetColorProfileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetColorProfileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ColorProfileChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorProfileChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ColorProfileChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ColorProfileChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ColorProfileChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ColorProfileChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayInformation2> : produce_base<D, Windows::Graphics::Display::IDisplayInformation2>
{
    int32_t WINRT_CALL get_RawPixelsPerViewPixel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawPixelsPerViewPixel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RawPixelsPerViewPixel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayInformation3> : produce_base<D, Windows::Graphics::Display::IDisplayInformation3>
{
    int32_t WINRT_CALL get_DiagonalSizeInInches(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiagonalSizeInInches, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().DiagonalSizeInInches());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayInformation4> : produce_base<D, Windows::Graphics::Display::IDisplayInformation4>
{
    int32_t WINRT_CALL get_ScreenWidthInRawPixels(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenWidthInRawPixels, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ScreenWidthInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScreenHeightInRawPixels(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenHeightInRawPixels, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ScreenHeightInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayInformation5> : produce_base<D, Windows::Graphics::Display::IDisplayInformation5>
{
    int32_t WINRT_CALL GetAdvancedColorInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAdvancedColorInfo, WINRT_WRAP(Windows::Graphics::Display::AdvancedColorInfo));
            *value = detach_from<Windows::Graphics::Display::AdvancedColorInfo>(this->shim().GetAdvancedColorInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AdvancedColorInfoChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvancedColorInfoChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AdvancedColorInfoChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AdvancedColorInfoChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AdvancedColorInfoChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AdvancedColorInfoChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayInformationStatics> : produce_base<D, Windows::Graphics::Display::IDisplayInformationStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** current) noexcept final
    {
        try
        {
            *current = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Graphics::Display::DisplayInformation));
            *current = detach_from<Windows::Graphics::Display::DisplayInformation>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRotationPreferences, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().AutoRotationPreferences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRotationPreferences, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().AutoRotationPreferences(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DisplayContentsInvalidated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayContentsInvalidated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DisplayContentsInvalidated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisplayContentsInvalidated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisplayContentsInvalidated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisplayContentsInvalidated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Display::IDisplayPropertiesStatics> : produce_base<D, Windows::Graphics::Display::IDisplayPropertiesStatics>
{
    int32_t WINRT_CALL get_CurrentOrientation(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentOrientation, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().CurrentOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NativeOrientation(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NativeOrientation, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().NativeOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRotationPreferences, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().AutoRotationPreferences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRotationPreferences, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().AutoRotationPreferences(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OrientationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientationChanged, WINRT_WRAP(winrt::event_token), Windows::Graphics::Display::DisplayPropertiesEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().OrientationChanged(*reinterpret_cast<Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OrientationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OrientationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OrientationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_ResolutionScale(Windows::Graphics::Display::ResolutionScale* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolutionScale, WINRT_WRAP(Windows::Graphics::Display::ResolutionScale));
            *value = detach_from<Windows::Graphics::Display::ResolutionScale>(this->shim().ResolutionScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogicalDpi(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogicalDpi, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LogicalDpi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LogicalDpiChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogicalDpiChanged, WINRT_WRAP(winrt::event_token), Windows::Graphics::Display::DisplayPropertiesEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().LogicalDpiChanged(*reinterpret_cast<Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LogicalDpiChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LogicalDpiChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LogicalDpiChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_StereoEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StereoEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StereoEnabledChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Graphics::Display::DisplayPropertiesEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().StereoEnabledChanged(*reinterpret_cast<Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StereoEnabledChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StereoEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StereoEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetColorProfileAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetColorProfileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetColorProfileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ColorProfileChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorProfileChanged, WINRT_WRAP(winrt::event_token), Windows::Graphics::Display::DisplayPropertiesEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ColorProfileChanged(*reinterpret_cast<Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ColorProfileChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ColorProfileChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ColorProfileChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DisplayContentsInvalidated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayContentsInvalidated, WINRT_WRAP(winrt::event_token), Windows::Graphics::Display::DisplayPropertiesEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DisplayContentsInvalidated(*reinterpret_cast<Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisplayContentsInvalidated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisplayContentsInvalidated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisplayContentsInvalidated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Display {

inline Windows::Graphics::Display::BrightnessOverride BrightnessOverride::GetDefaultForSystem()
{
    return impl::call_factory<BrightnessOverride, Windows::Graphics::Display::IBrightnessOverrideStatics>([&](auto&& f) { return f.GetDefaultForSystem(); });
}

inline Windows::Graphics::Display::BrightnessOverride BrightnessOverride::GetForCurrentView()
{
    return impl::call_factory<BrightnessOverride, Windows::Graphics::Display::IBrightnessOverrideStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Foundation::IAsyncOperation<bool> BrightnessOverride::SaveForSystemAsync(Windows::Graphics::Display::BrightnessOverride const& value)
{
    return impl::call_factory<BrightnessOverride, Windows::Graphics::Display::IBrightnessOverrideStatics>([&](auto&& f) { return f.SaveForSystemAsync(value); });
}

inline Windows::Graphics::Display::BrightnessOverrideSettings BrightnessOverrideSettings::CreateFromLevel(double level)
{
    return impl::call_factory<BrightnessOverrideSettings, Windows::Graphics::Display::IBrightnessOverrideSettingsStatics>([&](auto&& f) { return f.CreateFromLevel(level); });
}

inline Windows::Graphics::Display::BrightnessOverrideSettings BrightnessOverrideSettings::CreateFromNits(float nits)
{
    return impl::call_factory<BrightnessOverrideSettings, Windows::Graphics::Display::IBrightnessOverrideSettingsStatics>([&](auto&& f) { return f.CreateFromNits(nits); });
}

inline Windows::Graphics::Display::BrightnessOverrideSettings BrightnessOverrideSettings::CreateFromDisplayBrightnessOverrideScenario(Windows::Graphics::Display::DisplayBrightnessOverrideScenario const& overrideScenario)
{
    return impl::call_factory<BrightnessOverrideSettings, Windows::Graphics::Display::IBrightnessOverrideSettingsStatics>([&](auto&& f) { return f.CreateFromDisplayBrightnessOverrideScenario(overrideScenario); });
}

inline Windows::Graphics::Display::ColorOverrideSettings ColorOverrideSettings::CreateFromDisplayColorOverrideScenario(Windows::Graphics::Display::DisplayColorOverrideScenario const& overrideScenario)
{
    return impl::call_factory<ColorOverrideSettings, Windows::Graphics::Display::IColorOverrideSettingsStatics>([&](auto&& f) { return f.CreateFromDisplayColorOverrideScenario(overrideScenario); });
}

inline Windows::Graphics::Display::DisplayEnhancementOverride DisplayEnhancementOverride::GetForCurrentView()
{
    return impl::call_factory<DisplayEnhancementOverride, Windows::Graphics::Display::IDisplayEnhancementOverrideStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Graphics::Display::DisplayInformation DisplayInformation::GetForCurrentView()
{
    return impl::call_factory<DisplayInformation, Windows::Graphics::Display::IDisplayInformationStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Graphics::Display::DisplayOrientations DisplayInformation::AutoRotationPreferences()
{
    return impl::call_factory<DisplayInformation, Windows::Graphics::Display::IDisplayInformationStatics>([&](auto&& f) { return f.AutoRotationPreferences(); });
}

inline void DisplayInformation::AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations const& value)
{
    impl::call_factory<DisplayInformation, Windows::Graphics::Display::IDisplayInformationStatics>([&](auto&& f) { return f.AutoRotationPreferences(value); });
}

inline winrt::event_token DisplayInformation::DisplayContentsInvalidated(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<DisplayInformation, Windows::Graphics::Display::IDisplayInformationStatics>([&](auto&& f) { return f.DisplayContentsInvalidated(handler); });
}

inline DisplayInformation::DisplayContentsInvalidated_revoker DisplayInformation::DisplayContentsInvalidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<DisplayInformation, Windows::Graphics::Display::IDisplayInformationStatics>();
    return { f, f.DisplayContentsInvalidated(handler) };
}

inline void DisplayInformation::DisplayContentsInvalidated(winrt::event_token const& token)
{
    impl::call_factory<DisplayInformation, Windows::Graphics::Display::IDisplayInformationStatics>([&](auto&& f) { return f.DisplayContentsInvalidated(token); });
}

inline Windows::Graphics::Display::DisplayOrientations DisplayProperties::CurrentOrientation()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.CurrentOrientation(); });
}

inline Windows::Graphics::Display::DisplayOrientations DisplayProperties::NativeOrientation()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.NativeOrientation(); });
}

inline Windows::Graphics::Display::DisplayOrientations DisplayProperties::AutoRotationPreferences()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.AutoRotationPreferences(); });
}

inline void DisplayProperties::AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations const& value)
{
    impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.AutoRotationPreferences(value); });
}

inline winrt::event_token DisplayProperties::OrientationChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.OrientationChanged(handler); });
}

inline DisplayProperties::OrientationChanged_revoker DisplayProperties::OrientationChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    auto f = get_activation_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>();
    return { f, f.OrientationChanged(handler) };
}

inline void DisplayProperties::OrientationChanged(winrt::event_token const& token)
{
    impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.OrientationChanged(token); });
}

inline Windows::Graphics::Display::ResolutionScale DisplayProperties::ResolutionScale()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.ResolutionScale(); });
}

inline float DisplayProperties::LogicalDpi()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.LogicalDpi(); });
}

inline winrt::event_token DisplayProperties::LogicalDpiChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.LogicalDpiChanged(handler); });
}

inline DisplayProperties::LogicalDpiChanged_revoker DisplayProperties::LogicalDpiChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    auto f = get_activation_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>();
    return { f, f.LogicalDpiChanged(handler) };
}

inline void DisplayProperties::LogicalDpiChanged(winrt::event_token const& token)
{
    impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.LogicalDpiChanged(token); });
}

inline bool DisplayProperties::StereoEnabled()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.StereoEnabled(); });
}

inline winrt::event_token DisplayProperties::StereoEnabledChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.StereoEnabledChanged(handler); });
}

inline DisplayProperties::StereoEnabledChanged_revoker DisplayProperties::StereoEnabledChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    auto f = get_activation_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>();
    return { f, f.StereoEnabledChanged(handler) };
}

inline void DisplayProperties::StereoEnabledChanged(winrt::event_token const& token)
{
    impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.StereoEnabledChanged(token); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> DisplayProperties::GetColorProfileAsync()
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.GetColorProfileAsync(); });
}

inline winrt::event_token DisplayProperties::ColorProfileChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.ColorProfileChanged(handler); });
}

inline DisplayProperties::ColorProfileChanged_revoker DisplayProperties::ColorProfileChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    auto f = get_activation_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>();
    return { f, f.ColorProfileChanged(handler) };
}

inline void DisplayProperties::ColorProfileChanged(winrt::event_token const& token)
{
    impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.ColorProfileChanged(token); });
}

inline winrt::event_token DisplayProperties::DisplayContentsInvalidated(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    return impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.DisplayContentsInvalidated(handler); });
}

inline DisplayProperties::DisplayContentsInvalidated_revoker DisplayProperties::DisplayContentsInvalidated(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
{
    auto f = get_activation_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>();
    return { f, f.DisplayContentsInvalidated(handler) };
}

inline void DisplayProperties::DisplayContentsInvalidated(winrt::event_token const& token)
{
    impl::call_factory<DisplayProperties, Windows::Graphics::Display::IDisplayPropertiesStatics>([&](auto&& f) { return f.DisplayContentsInvalidated(token); });
}

template <typename L> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(L handler) :
    DisplayPropertiesEventHandler(impl::make_delegate<DisplayPropertiesEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(F* handler) :
    DisplayPropertiesEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(O* object, M method) :
    DisplayPropertiesEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(com_ptr<O>&& object, M method) :
    DisplayPropertiesEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(weak_ref<O>&& object, M method) :
    DisplayPropertiesEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DisplayPropertiesEventHandler::operator()(Windows::Foundation::IInspectable const& sender) const
{
    check_hresult((*(impl::abi_t<DisplayPropertiesEventHandler>**)this)->Invoke(get_abi(sender)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Display::IAdvancedColorInfo> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IAdvancedColorInfo> {};
template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverride> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IBrightnessOverride> {};
template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverrideSettings> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IBrightnessOverrideSettings> {};
template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverrideStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IBrightnessOverrideStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::IColorOverrideSettings> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IColorOverrideSettings> {};
template<> struct hash<winrt::Windows::Graphics::Display::IColorOverrideSettingsStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IColorOverrideSettingsStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverride> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayEnhancementOverride> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayInformation> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation2> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayInformation2> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation3> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayInformation3> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation4> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayInformation4> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation5> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayInformation5> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformationStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayInformationStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::IDisplayPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::IDisplayPropertiesStatics> {};
template<> struct hash<winrt::Windows::Graphics::Display::AdvancedColorInfo> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::AdvancedColorInfo> {};
template<> struct hash<winrt::Windows::Graphics::Display::BrightnessOverride> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::BrightnessOverride> {};
template<> struct hash<winrt::Windows::Graphics::Display::BrightnessOverrideSettings> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::BrightnessOverrideSettings> {};
template<> struct hash<winrt::Windows::Graphics::Display::ColorOverrideSettings> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::ColorOverrideSettings> {};
template<> struct hash<winrt::Windows::Graphics::Display::DisplayEnhancementOverride> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::DisplayEnhancementOverride> {};
template<> struct hash<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities> {};
template<> struct hash<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Display::DisplayInformation> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::DisplayInformation> {};
template<> struct hash<winrt::Windows::Graphics::Display::DisplayProperties> : winrt::impl::hash_base<winrt::Windows::Graphics::Display::DisplayProperties> {};

}
