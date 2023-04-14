// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Graphics.Display.1.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Display {

struct DisplayPropertiesEventHandler : Windows::Foundation::IUnknown
{
    DisplayPropertiesEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> DisplayPropertiesEventHandler(L lambda);
    template <typename F> DisplayPropertiesEventHandler(F* function);
    template <typename O, typename M> DisplayPropertiesEventHandler(O* object, M method);
    template <typename O, typename M> DisplayPropertiesEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> DisplayPropertiesEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender) const;
};

struct NitRange
{
    float MinNits;
    float MaxNits;
    float StepSizeNits;
};

inline bool operator==(NitRange const& left, NitRange const& right) noexcept
{
    return left.MinNits == right.MinNits && left.MaxNits == right.MaxNits && left.StepSizeNits == right.StepSizeNits;
}

inline bool operator!=(NitRange const& left, NitRange const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Display {

struct WINRT_EBO AdvancedColorInfo :
    Windows::Graphics::Display::IAdvancedColorInfo
{
    AdvancedColorInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BrightnessOverride :
    Windows::Graphics::Display::IBrightnessOverride
{
    BrightnessOverride(std::nullptr_t) noexcept {}
    static Windows::Graphics::Display::BrightnessOverride GetDefaultForSystem();
    static Windows::Graphics::Display::BrightnessOverride GetForCurrentView();
    static Windows::Foundation::IAsyncOperation<bool> SaveForSystemAsync(Windows::Graphics::Display::BrightnessOverride const& value);
};

struct WINRT_EBO BrightnessOverrideSettings :
    Windows::Graphics::Display::IBrightnessOverrideSettings
{
    BrightnessOverrideSettings(std::nullptr_t) noexcept {}
    static Windows::Graphics::Display::BrightnessOverrideSettings CreateFromLevel(double level);
    static Windows::Graphics::Display::BrightnessOverrideSettings CreateFromNits(float nits);
    static Windows::Graphics::Display::BrightnessOverrideSettings CreateFromDisplayBrightnessOverrideScenario(Windows::Graphics::Display::DisplayBrightnessOverrideScenario const& overrideScenario);
};

struct WINRT_EBO ColorOverrideSettings :
    Windows::Graphics::Display::IColorOverrideSettings
{
    ColorOverrideSettings(std::nullptr_t) noexcept {}
    static Windows::Graphics::Display::ColorOverrideSettings CreateFromDisplayColorOverrideScenario(Windows::Graphics::Display::DisplayColorOverrideScenario const& overrideScenario);
};

struct WINRT_EBO DisplayEnhancementOverride :
    Windows::Graphics::Display::IDisplayEnhancementOverride
{
    DisplayEnhancementOverride(std::nullptr_t) noexcept {}
    static Windows::Graphics::Display::DisplayEnhancementOverride GetForCurrentView();
};

struct WINRT_EBO DisplayEnhancementOverrideCapabilities :
    Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities
{
    DisplayEnhancementOverrideCapabilities(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayEnhancementOverrideCapabilitiesChangedEventArgs :
    Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs
{
    DisplayEnhancementOverrideCapabilitiesChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayInformation :
    Windows::Graphics::Display::IDisplayInformation,
    impl::require<DisplayInformation, Windows::Graphics::Display::IDisplayInformation2, Windows::Graphics::Display::IDisplayInformation3, Windows::Graphics::Display::IDisplayInformation4, Windows::Graphics::Display::IDisplayInformation5>
{
    DisplayInformation(std::nullptr_t) noexcept {}
    static Windows::Graphics::Display::DisplayInformation GetForCurrentView();
    static Windows::Graphics::Display::DisplayOrientations AutoRotationPreferences();
    static void AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations const& value);
    static winrt::event_token DisplayContentsInvalidated(Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler);
    using DisplayContentsInvalidated_revoker = impl::factory_event_revoker<Windows::Graphics::Display::IDisplayInformationStatics, &impl::abi_t<Windows::Graphics::Display::IDisplayInformationStatics>::remove_DisplayContentsInvalidated>;
    static DisplayContentsInvalidated_revoker DisplayContentsInvalidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Display::DisplayInformation, Windows::Foundation::IInspectable> const& handler);
    static void DisplayContentsInvalidated(winrt::event_token const& token);
};

struct DisplayProperties
{
    DisplayProperties() = delete;
    static Windows::Graphics::Display::DisplayOrientations CurrentOrientation();
    static Windows::Graphics::Display::DisplayOrientations NativeOrientation();
    static Windows::Graphics::Display::DisplayOrientations AutoRotationPreferences();
    static void AutoRotationPreferences(Windows::Graphics::Display::DisplayOrientations const& value);
    static winrt::event_token OrientationChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    using OrientationChanged_revoker = impl::factory_event_revoker<Windows::Graphics::Display::IDisplayPropertiesStatics, &impl::abi_t<Windows::Graphics::Display::IDisplayPropertiesStatics>::remove_OrientationChanged>;
    static OrientationChanged_revoker OrientationChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    static void OrientationChanged(winrt::event_token const& token);
    static Windows::Graphics::Display::ResolutionScale ResolutionScale();
    static float LogicalDpi();
    static winrt::event_token LogicalDpiChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    using LogicalDpiChanged_revoker = impl::factory_event_revoker<Windows::Graphics::Display::IDisplayPropertiesStatics, &impl::abi_t<Windows::Graphics::Display::IDisplayPropertiesStatics>::remove_LogicalDpiChanged>;
    static LogicalDpiChanged_revoker LogicalDpiChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    static void LogicalDpiChanged(winrt::event_token const& token);
    static bool StereoEnabled();
    static winrt::event_token StereoEnabledChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    using StereoEnabledChanged_revoker = impl::factory_event_revoker<Windows::Graphics::Display::IDisplayPropertiesStatics, &impl::abi_t<Windows::Graphics::Display::IDisplayPropertiesStatics>::remove_StereoEnabledChanged>;
    static StereoEnabledChanged_revoker StereoEnabledChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    static void StereoEnabledChanged(winrt::event_token const& token);
    static Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> GetColorProfileAsync();
    static winrt::event_token ColorProfileChanged(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    using ColorProfileChanged_revoker = impl::factory_event_revoker<Windows::Graphics::Display::IDisplayPropertiesStatics, &impl::abi_t<Windows::Graphics::Display::IDisplayPropertiesStatics>::remove_ColorProfileChanged>;
    static ColorProfileChanged_revoker ColorProfileChanged(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    static void ColorProfileChanged(winrt::event_token const& token);
    static winrt::event_token DisplayContentsInvalidated(Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    using DisplayContentsInvalidated_revoker = impl::factory_event_revoker<Windows::Graphics::Display::IDisplayPropertiesStatics, &impl::abi_t<Windows::Graphics::Display::IDisplayPropertiesStatics>::remove_DisplayContentsInvalidated>;
    static DisplayContentsInvalidated_revoker DisplayContentsInvalidated(auto_revoke_t, Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler);
    static void DisplayContentsInvalidated(winrt::event_token const& token);
};

}
