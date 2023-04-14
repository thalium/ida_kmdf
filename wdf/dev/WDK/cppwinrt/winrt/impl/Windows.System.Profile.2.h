// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.System.Profile.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Profile {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Profile {

struct AnalyticsInfo
{
    AnalyticsInfo() = delete;
    static Windows::System::Profile::AnalyticsVersionInfo VersionInfo();
    static hstring DeviceForm();
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, hstring>> GetSystemPropertiesAsync(param::async_iterable<hstring> const& attributeNames);
};

struct WINRT_EBO AnalyticsVersionInfo :
    Windows::System::Profile::IAnalyticsVersionInfo
{
    AnalyticsVersionInfo(std::nullptr_t) noexcept {}
};

struct AppApplicability
{
    AppApplicability() = delete;
    static Windows::Foundation::Collections::IVectorView<Windows::System::Profile::UnsupportedAppRequirement> GetUnsupportedAppRequirements(param::iterable<hstring> const& capabilities);
};

struct EducationSettings
{
    EducationSettings() = delete;
    static bool IsEducationEnvironment();
};

struct HardwareIdentification
{
    HardwareIdentification() = delete;
    static Windows::System::Profile::HardwareToken GetPackageSpecificToken(Windows::Storage::Streams::IBuffer const& nonce);
};

struct WINRT_EBO HardwareToken :
    Windows::System::Profile::IHardwareToken
{
    HardwareToken(std::nullptr_t) noexcept {}
};

struct KnownRetailInfoProperties
{
    KnownRetailInfoProperties() = delete;
    static hstring RetailAccessCode();
    static hstring ManufacturerName();
    static hstring ModelName();
    static hstring DisplayModelName();
    static hstring Price();
    static hstring IsFeatured();
    static hstring FormFactor();
    static hstring ScreenSize();
    static hstring Weight();
    static hstring DisplayDescription();
    static hstring BatteryLifeDescription();
    static hstring ProcessorDescription();
    static hstring Memory();
    static hstring StorageDescription();
    static hstring GraphicsDescription();
    static hstring FrontCameraDescription();
    static hstring RearCameraDescription();
    static hstring HasNfc();
    static hstring HasSdSlot();
    static hstring HasOpticalDrive();
    static hstring IsOfficeInstalled();
    static hstring WindowsEdition();
};

struct PlatformDiagnosticsAndUsageDataSettings
{
    PlatformDiagnosticsAndUsageDataSettings() = delete;
    static Windows::System::Profile::PlatformDataCollectionLevel CollectionLevel();
    static winrt::event_token CollectionLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using CollectionLevelChanged_revoker = impl::factory_event_revoker<Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics, &impl::abi_t<Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>::remove_CollectionLevelChanged>;
    static CollectionLevelChanged_revoker CollectionLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void CollectionLevelChanged(winrt::event_token const& token);
    static bool CanCollectDiagnostics(Windows::System::Profile::PlatformDataCollectionLevel const& level);
};

struct RetailInfo
{
    RetailInfo() = delete;
    static bool IsDemoModeEnabled();
    static Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Properties();
};

struct SharedModeSettings
{
    SharedModeSettings() = delete;
    static bool IsEnabled();
    static bool ShouldAvoidLocalStorage();
};

struct SystemIdentification
{
    SystemIdentification() = delete;
    static Windows::System::Profile::SystemIdentificationInfo GetSystemIdForPublisher();
    static Windows::System::Profile::SystemIdentificationInfo GetSystemIdForUser(Windows::System::User const& user);
};

struct WINRT_EBO SystemIdentificationInfo :
    Windows::System::Profile::ISystemIdentificationInfo
{
    SystemIdentificationInfo(std::nullptr_t) noexcept {}
};

struct SystemSetupInfo
{
    SystemSetupInfo() = delete;
    static Windows::System::Profile::SystemOutOfBoxExperienceState OutOfBoxExperienceState();
    static winrt::event_token OutOfBoxExperienceStateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using OutOfBoxExperienceStateChanged_revoker = impl::factory_event_revoker<Windows::System::Profile::ISystemSetupInfoStatics, &impl::abi_t<Windows::System::Profile::ISystemSetupInfoStatics>::remove_OutOfBoxExperienceStateChanged>;
    static OutOfBoxExperienceStateChanged_revoker OutOfBoxExperienceStateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void OutOfBoxExperienceStateChanged(winrt::event_token const& token);
};

struct WINRT_EBO UnsupportedAppRequirement :
    Windows::System::Profile::IUnsupportedAppRequirement
{
    UnsupportedAppRequirement(std::nullptr_t) noexcept {}
};

struct WindowsIntegrityPolicy
{
    WindowsIntegrityPolicy() = delete;
    static bool IsEnabled();
    static bool IsEnabledForTrial();
    static bool CanDisable();
    static bool IsDisableSupported();
    static winrt::event_token PolicyChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using PolicyChanged_revoker = impl::factory_event_revoker<Windows::System::Profile::IWindowsIntegrityPolicyStatics, &impl::abi_t<Windows::System::Profile::IWindowsIntegrityPolicyStatics>::remove_PolicyChanged>;
    static PolicyChanged_revoker PolicyChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void PolicyChanged(winrt::event_token const& token);
};

}
