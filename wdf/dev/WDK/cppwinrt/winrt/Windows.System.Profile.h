// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.System.Profile.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> Windows::System::Profile::AnalyticsVersionInfo consume_Windows_System_Profile_IAnalyticsInfoStatics<D>::VersionInfo() const
{
    Windows::System::Profile::AnalyticsVersionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IAnalyticsInfoStatics)->get_VersionInfo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IAnalyticsInfoStatics<D>::DeviceForm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IAnalyticsInfoStatics)->get_DeviceForm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, hstring>> consume_Windows_System_Profile_IAnalyticsInfoStatics2<D>::GetSystemPropertiesAsync(param::async_iterable<hstring> const& attributeNames) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, hstring>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IAnalyticsInfoStatics2)->GetSystemPropertiesAsync(get_abi(attributeNames), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_System_Profile_IAnalyticsVersionInfo<D>::DeviceFamily() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IAnalyticsVersionInfo)->get_DeviceFamily(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IAnalyticsVersionInfo<D>::DeviceFamilyVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IAnalyticsVersionInfo)->get_DeviceFamilyVersion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::Profile::UnsupportedAppRequirement> consume_Windows_System_Profile_IAppApplicabilityStatics<D>::GetUnsupportedAppRequirements(param::iterable<hstring> const& capabilities) const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::Profile::UnsupportedAppRequirement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IAppApplicabilityStatics)->GetUnsupportedAppRequirements(get_abi(capabilities), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_System_Profile_IEducationSettingsStatics<D>::IsEducationEnvironment() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IEducationSettingsStatics)->get_IsEducationEnvironment(&value));
    return value;
}

template <typename D> Windows::System::Profile::HardwareToken consume_Windows_System_Profile_IHardwareIdentificationStatics<D>::GetPackageSpecificToken(Windows::Storage::Streams::IBuffer const& nonce) const
{
    Windows::System::Profile::HardwareToken packageSpecificHardwareToken{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IHardwareIdentificationStatics)->GetPackageSpecificToken(get_abi(nonce), put_abi(packageSpecificHardwareToken)));
    return packageSpecificHardwareToken;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_System_Profile_IHardwareToken<D>::Id() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IHardwareToken)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_System_Profile_IHardwareToken<D>::Signature() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IHardwareToken)->get_Signature(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_System_Profile_IHardwareToken<D>::Certificate() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IHardwareToken)->get_Certificate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::RetailAccessCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_RetailAccessCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::ManufacturerName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_ManufacturerName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::ModelName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_ModelName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::DisplayModelName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_DisplayModelName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::Price() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_Price(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::IsFeatured() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_IsFeatured(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::FormFactor() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_FormFactor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::ScreenSize() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_ScreenSize(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::Weight() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_Weight(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::DisplayDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_DisplayDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::BatteryLifeDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_BatteryLifeDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::ProcessorDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_ProcessorDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::Memory() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_Memory(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::StorageDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_StorageDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::GraphicsDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_GraphicsDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::FrontCameraDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_FrontCameraDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::RearCameraDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_RearCameraDescription(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::HasNfc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_HasNfc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::HasSdSlot() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_HasSdSlot(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::HasOpticalDrive() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_HasOpticalDrive(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::IsOfficeInstalled() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_IsOfficeInstalled(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_IKnownRetailInfoPropertiesStatics<D>::WindowsEdition() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IKnownRetailInfoPropertiesStatics)->get_WindowsEdition(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Profile::PlatformDataCollectionLevel consume_Windows_System_Profile_IPlatformDiagnosticsAndUsageDataSettingsStatics<D>::CollectionLevel() const
{
    Windows::System::Profile::PlatformDataCollectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics)->get_CollectionLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Profile_IPlatformDiagnosticsAndUsageDataSettingsStatics<D>::CollectionLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics)->add_CollectionLevelChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Profile_IPlatformDiagnosticsAndUsageDataSettingsStatics<D>::CollectionLevelChanged_revoker consume_Windows_System_Profile_IPlatformDiagnosticsAndUsageDataSettingsStatics<D>::CollectionLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CollectionLevelChanged_revoker>(this, CollectionLevelChanged(handler));
}

template <typename D> void consume_Windows_System_Profile_IPlatformDiagnosticsAndUsageDataSettingsStatics<D>::CollectionLevelChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics)->remove_CollectionLevelChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_System_Profile_IPlatformDiagnosticsAndUsageDataSettingsStatics<D>::CanCollectDiagnostics(Windows::System::Profile::PlatformDataCollectionLevel const& level) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics)->CanCollectDiagnostics(get_abi(level), &result));
    return result;
}

template <typename D> bool consume_Windows_System_Profile_IRetailInfoStatics<D>::IsDemoModeEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IRetailInfoStatics)->get_IsDemoModeEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_System_Profile_IRetailInfoStatics<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::IRetailInfoStatics)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_Profile_ISharedModeSettingsStatics<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISharedModeSettingsStatics)->get_IsEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Profile_ISharedModeSettingsStatics2<D>::ShouldAvoidLocalStorage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISharedModeSettingsStatics2)->get_ShouldAvoidLocalStorage(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_System_Profile_ISystemIdentificationInfo<D>::Id() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISystemIdentificationInfo)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Profile::SystemIdentificationSource consume_Windows_System_Profile_ISystemIdentificationInfo<D>::Source() const
{
    Windows::System::Profile::SystemIdentificationSource value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISystemIdentificationInfo)->get_Source(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Profile::SystemIdentificationInfo consume_Windows_System_Profile_ISystemIdentificationStatics<D>::GetSystemIdForPublisher() const
{
    Windows::System::Profile::SystemIdentificationInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISystemIdentificationStatics)->GetSystemIdForPublisher(put_abi(result)));
    return result;
}

template <typename D> Windows::System::Profile::SystemIdentificationInfo consume_Windows_System_Profile_ISystemIdentificationStatics<D>::GetSystemIdForUser(Windows::System::User const& user) const
{
    Windows::System::Profile::SystemIdentificationInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISystemIdentificationStatics)->GetSystemIdForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::System::Profile::SystemOutOfBoxExperienceState consume_Windows_System_Profile_ISystemSetupInfoStatics<D>::OutOfBoxExperienceState() const
{
    Windows::System::Profile::SystemOutOfBoxExperienceState value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISystemSetupInfoStatics)->get_OutOfBoxExperienceState(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Profile_ISystemSetupInfoStatics<D>::OutOfBoxExperienceStateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::ISystemSetupInfoStatics)->add_OutOfBoxExperienceStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Profile_ISystemSetupInfoStatics<D>::OutOfBoxExperienceStateChanged_revoker consume_Windows_System_Profile_ISystemSetupInfoStatics<D>::OutOfBoxExperienceStateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, OutOfBoxExperienceStateChanged_revoker>(this, OutOfBoxExperienceStateChanged(handler));
}

template <typename D> void consume_Windows_System_Profile_ISystemSetupInfoStatics<D>::OutOfBoxExperienceStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Profile::ISystemSetupInfoStatics)->remove_OutOfBoxExperienceStateChanged(get_abi(token)));
}

template <typename D> hstring consume_Windows_System_Profile_IUnsupportedAppRequirement<D>::Requirement() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IUnsupportedAppRequirement)->get_Requirement(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Profile::UnsupportedAppRequirementReasons consume_Windows_System_Profile_IUnsupportedAppRequirement<D>::Reasons() const
{
    Windows::System::Profile::UnsupportedAppRequirementReasons value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IUnsupportedAppRequirement)->get_Reasons(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IWindowsIntegrityPolicyStatics)->get_IsEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::IsEnabledForTrial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IWindowsIntegrityPolicyStatics)->get_IsEnabledForTrial(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::CanDisable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IWindowsIntegrityPolicyStatics)->get_CanDisable(&value));
    return value;
}

template <typename D> bool consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::IsDisableSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IWindowsIntegrityPolicyStatics)->get_IsDisableSupported(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::PolicyChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::IWindowsIntegrityPolicyStatics)->add_PolicyChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::PolicyChanged_revoker consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::PolicyChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PolicyChanged_revoker>(this, PolicyChanged(handler));
}

template <typename D> void consume_Windows_System_Profile_IWindowsIntegrityPolicyStatics<D>::PolicyChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Profile::IWindowsIntegrityPolicyStatics)->remove_PolicyChanged(get_abi(token)));
}

template <typename D>
struct produce<D, Windows::System::Profile::IAnalyticsInfoStatics> : produce_base<D, Windows::System::Profile::IAnalyticsInfoStatics>
{
    int32_t WINRT_CALL get_VersionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VersionInfo, WINRT_WRAP(Windows::System::Profile::AnalyticsVersionInfo));
            *value = detach_from<Windows::System::Profile::AnalyticsVersionInfo>(this->shim().VersionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceForm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceForm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceForm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IAnalyticsInfoStatics2> : produce_base<D, Windows::System::Profile::IAnalyticsInfoStatics2>
{
    int32_t WINRT_CALL GetSystemPropertiesAsync(void* attributeNames, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, hstring>>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, hstring>>>(this->shim().GetSystemPropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&attributeNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IAnalyticsVersionInfo> : produce_base<D, Windows::System::Profile::IAnalyticsVersionInfo>
{
    int32_t WINRT_CALL get_DeviceFamily(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceFamily, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceFamilyVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceFamilyVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceFamilyVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IAppApplicabilityStatics> : produce_base<D, Windows::System::Profile::IAppApplicabilityStatics>
{
    int32_t WINRT_CALL GetUnsupportedAppRequirements(void* capabilities, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUnsupportedAppRequirements, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::Profile::UnsupportedAppRequirement>), Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::Profile::UnsupportedAppRequirement>>(this->shim().GetUnsupportedAppRequirements(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&capabilities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IEducationSettingsStatics> : produce_base<D, Windows::System::Profile::IEducationSettingsStatics>
{
    int32_t WINRT_CALL get_IsEducationEnvironment(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEducationEnvironment, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEducationEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IHardwareIdentificationStatics> : produce_base<D, Windows::System::Profile::IHardwareIdentificationStatics>
{
    int32_t WINRT_CALL GetPackageSpecificToken(void* nonce, void** packageSpecificHardwareToken) noexcept final
    {
        try
        {
            *packageSpecificHardwareToken = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPackageSpecificToken, WINRT_WRAP(Windows::System::Profile::HardwareToken), Windows::Storage::Streams::IBuffer const&);
            *packageSpecificHardwareToken = detach_from<Windows::System::Profile::HardwareToken>(this->shim().GetPackageSpecificToken(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&nonce)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IHardwareToken> : produce_base<D, Windows::System::Profile::IHardwareToken>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Signature(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Signature, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Signature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Certificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Certificate, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Certificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IKnownRetailInfoPropertiesStatics> : produce_base<D, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>
{
    int32_t WINRT_CALL get_RetailAccessCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetailAccessCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RetailAccessCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManufacturerName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ManufacturerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayModelName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayModelName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Price(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Price, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFeatured(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFeatured, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IsFeatured());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FormFactor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormFactor, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScreenSize(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenSize, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ScreenSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Weight(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BatteryLifeDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatteryLifeDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BatteryLifeDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProcessorDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessorDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProcessorDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Memory(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Memory, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Memory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorageDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StorageDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GraphicsDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GraphicsDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GraphicsDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrontCameraDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrontCameraDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FrontCameraDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RearCameraDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RearCameraDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RearCameraDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNfc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNfc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HasNfc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasSdSlot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasSdSlot, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HasSdSlot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasOpticalDrive(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasOpticalDrive, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HasOpticalDrive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOfficeInstalled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOfficeInstalled, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IsOfficeInstalled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WindowsEdition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowsEdition, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WindowsEdition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics> : produce_base<D, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>
{
    int32_t WINRT_CALL get_CollectionLevel(Windows::System::Profile::PlatformDataCollectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollectionLevel, WINRT_WRAP(Windows::System::Profile::PlatformDataCollectionLevel));
            *value = detach_from<Windows::System::Profile::PlatformDataCollectionLevel>(this->shim().CollectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CollectionLevelChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollectionLevelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CollectionLevelChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CollectionLevelChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CollectionLevelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CollectionLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CanCollectDiagnostics(Windows::System::Profile::PlatformDataCollectionLevel level, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCollectDiagnostics, WINRT_WRAP(bool), Windows::System::Profile::PlatformDataCollectionLevel const&);
            *result = detach_from<bool>(this->shim().CanCollectDiagnostics(*reinterpret_cast<Windows::System::Profile::PlatformDataCollectionLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IRetailInfoStatics> : produce_base<D, Windows::System::Profile::IRetailInfoStatics>
{
    int32_t WINRT_CALL get_IsDemoModeEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDemoModeEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDemoModeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::ISharedModeSettingsStatics> : produce_base<D, Windows::System::Profile::ISharedModeSettingsStatics>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::ISharedModeSettingsStatics2> : produce_base<D, Windows::System::Profile::ISharedModeSettingsStatics2>
{
    int32_t WINRT_CALL get_ShouldAvoidLocalStorage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldAvoidLocalStorage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldAvoidLocalStorage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::ISystemIdentificationInfo> : produce_base<D, Windows::System::Profile::ISystemIdentificationInfo>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(Windows::System::Profile::SystemIdentificationSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::System::Profile::SystemIdentificationSource));
            *value = detach_from<Windows::System::Profile::SystemIdentificationSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::ISystemIdentificationStatics> : produce_base<D, Windows::System::Profile::ISystemIdentificationStatics>
{
    int32_t WINRT_CALL GetSystemIdForPublisher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemIdForPublisher, WINRT_WRAP(Windows::System::Profile::SystemIdentificationInfo));
            *result = detach_from<Windows::System::Profile::SystemIdentificationInfo>(this->shim().GetSystemIdForPublisher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSystemIdForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemIdForUser, WINRT_WRAP(Windows::System::Profile::SystemIdentificationInfo), Windows::System::User const&);
            *result = detach_from<Windows::System::Profile::SystemIdentificationInfo>(this->shim().GetSystemIdForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::ISystemSetupInfoStatics> : produce_base<D, Windows::System::Profile::ISystemSetupInfoStatics>
{
    int32_t WINRT_CALL get_OutOfBoxExperienceState(Windows::System::Profile::SystemOutOfBoxExperienceState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutOfBoxExperienceState, WINRT_WRAP(Windows::System::Profile::SystemOutOfBoxExperienceState));
            *value = detach_from<Windows::System::Profile::SystemOutOfBoxExperienceState>(this->shim().OutOfBoxExperienceState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OutOfBoxExperienceStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutOfBoxExperienceStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().OutOfBoxExperienceStateChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OutOfBoxExperienceStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OutOfBoxExperienceStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OutOfBoxExperienceStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IUnsupportedAppRequirement> : produce_base<D, Windows::System::Profile::IUnsupportedAppRequirement>
{
    int32_t WINRT_CALL get_Requirement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Requirement, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Requirement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reasons(Windows::System::Profile::UnsupportedAppRequirementReasons* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reasons, WINRT_WRAP(Windows::System::Profile::UnsupportedAppRequirementReasons));
            *value = detach_from<Windows::System::Profile::UnsupportedAppRequirementReasons>(this->shim().Reasons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::IWindowsIntegrityPolicyStatics> : produce_base<D, Windows::System::Profile::IWindowsIntegrityPolicyStatics>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabledForTrial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabledForTrial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabledForTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDisable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDisable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDisable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisableSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisableSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisableSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PolicyChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PolicyChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PolicyChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PolicyChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PolicyChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PolicyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Profile {

inline Windows::System::Profile::AnalyticsVersionInfo AnalyticsInfo::VersionInfo()
{
    return impl::call_factory<AnalyticsInfo, Windows::System::Profile::IAnalyticsInfoStatics>([&](auto&& f) { return f.VersionInfo(); });
}

inline hstring AnalyticsInfo::DeviceForm()
{
    return impl::call_factory<AnalyticsInfo, Windows::System::Profile::IAnalyticsInfoStatics>([&](auto&& f) { return f.DeviceForm(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, hstring>> AnalyticsInfo::GetSystemPropertiesAsync(param::async_iterable<hstring> const& attributeNames)
{
    return impl::call_factory<AnalyticsInfo, Windows::System::Profile::IAnalyticsInfoStatics2>([&](auto&& f) { return f.GetSystemPropertiesAsync(attributeNames); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::System::Profile::UnsupportedAppRequirement> AppApplicability::GetUnsupportedAppRequirements(param::iterable<hstring> const& capabilities)
{
    return impl::call_factory<AppApplicability, Windows::System::Profile::IAppApplicabilityStatics>([&](auto&& f) { return f.GetUnsupportedAppRequirements(capabilities); });
}

inline bool EducationSettings::IsEducationEnvironment()
{
    return impl::call_factory<EducationSettings, Windows::System::Profile::IEducationSettingsStatics>([&](auto&& f) { return f.IsEducationEnvironment(); });
}

inline Windows::System::Profile::HardwareToken HardwareIdentification::GetPackageSpecificToken(Windows::Storage::Streams::IBuffer const& nonce)
{
    return impl::call_factory<HardwareIdentification, Windows::System::Profile::IHardwareIdentificationStatics>([&](auto&& f) { return f.GetPackageSpecificToken(nonce); });
}

inline hstring KnownRetailInfoProperties::RetailAccessCode()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.RetailAccessCode(); });
}

inline hstring KnownRetailInfoProperties::ManufacturerName()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.ManufacturerName(); });
}

inline hstring KnownRetailInfoProperties::ModelName()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.ModelName(); });
}

inline hstring KnownRetailInfoProperties::DisplayModelName()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.DisplayModelName(); });
}

inline hstring KnownRetailInfoProperties::Price()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.Price(); });
}

inline hstring KnownRetailInfoProperties::IsFeatured()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.IsFeatured(); });
}

inline hstring KnownRetailInfoProperties::FormFactor()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.FormFactor(); });
}

inline hstring KnownRetailInfoProperties::ScreenSize()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.ScreenSize(); });
}

inline hstring KnownRetailInfoProperties::Weight()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.Weight(); });
}

inline hstring KnownRetailInfoProperties::DisplayDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.DisplayDescription(); });
}

inline hstring KnownRetailInfoProperties::BatteryLifeDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.BatteryLifeDescription(); });
}

inline hstring KnownRetailInfoProperties::ProcessorDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.ProcessorDescription(); });
}

inline hstring KnownRetailInfoProperties::Memory()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.Memory(); });
}

inline hstring KnownRetailInfoProperties::StorageDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.StorageDescription(); });
}

inline hstring KnownRetailInfoProperties::GraphicsDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.GraphicsDescription(); });
}

inline hstring KnownRetailInfoProperties::FrontCameraDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.FrontCameraDescription(); });
}

inline hstring KnownRetailInfoProperties::RearCameraDescription()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.RearCameraDescription(); });
}

inline hstring KnownRetailInfoProperties::HasNfc()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.HasNfc(); });
}

inline hstring KnownRetailInfoProperties::HasSdSlot()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.HasSdSlot(); });
}

inline hstring KnownRetailInfoProperties::HasOpticalDrive()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.HasOpticalDrive(); });
}

inline hstring KnownRetailInfoProperties::IsOfficeInstalled()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.IsOfficeInstalled(); });
}

inline hstring KnownRetailInfoProperties::WindowsEdition()
{
    return impl::call_factory<KnownRetailInfoProperties, Windows::System::Profile::IKnownRetailInfoPropertiesStatics>([&](auto&& f) { return f.WindowsEdition(); });
}

inline Windows::System::Profile::PlatformDataCollectionLevel PlatformDiagnosticsAndUsageDataSettings::CollectionLevel()
{
    return impl::call_factory<PlatformDiagnosticsAndUsageDataSettings, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>([&](auto&& f) { return f.CollectionLevel(); });
}

inline winrt::event_token PlatformDiagnosticsAndUsageDataSettings::CollectionLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PlatformDiagnosticsAndUsageDataSettings, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>([&](auto&& f) { return f.CollectionLevelChanged(handler); });
}

inline PlatformDiagnosticsAndUsageDataSettings::CollectionLevelChanged_revoker PlatformDiagnosticsAndUsageDataSettings::CollectionLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PlatformDiagnosticsAndUsageDataSettings, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>();
    return { f, f.CollectionLevelChanged(handler) };
}

inline void PlatformDiagnosticsAndUsageDataSettings::CollectionLevelChanged(winrt::event_token const& token)
{
    impl::call_factory<PlatformDiagnosticsAndUsageDataSettings, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>([&](auto&& f) { return f.CollectionLevelChanged(token); });
}

inline bool PlatformDiagnosticsAndUsageDataSettings::CanCollectDiagnostics(Windows::System::Profile::PlatformDataCollectionLevel const& level)
{
    return impl::call_factory<PlatformDiagnosticsAndUsageDataSettings, Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics>([&](auto&& f) { return f.CanCollectDiagnostics(level); });
}

inline bool RetailInfo::IsDemoModeEnabled()
{
    return impl::call_factory<RetailInfo, Windows::System::Profile::IRetailInfoStatics>([&](auto&& f) { return f.IsDemoModeEnabled(); });
}

inline Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> RetailInfo::Properties()
{
    return impl::call_factory<RetailInfo, Windows::System::Profile::IRetailInfoStatics>([&](auto&& f) { return f.Properties(); });
}

inline bool SharedModeSettings::IsEnabled()
{
    return impl::call_factory<SharedModeSettings, Windows::System::Profile::ISharedModeSettingsStatics>([&](auto&& f) { return f.IsEnabled(); });
}

inline bool SharedModeSettings::ShouldAvoidLocalStorage()
{
    return impl::call_factory<SharedModeSettings, Windows::System::Profile::ISharedModeSettingsStatics2>([&](auto&& f) { return f.ShouldAvoidLocalStorage(); });
}

inline Windows::System::Profile::SystemIdentificationInfo SystemIdentification::GetSystemIdForPublisher()
{
    return impl::call_factory<SystemIdentification, Windows::System::Profile::ISystemIdentificationStatics>([&](auto&& f) { return f.GetSystemIdForPublisher(); });
}

inline Windows::System::Profile::SystemIdentificationInfo SystemIdentification::GetSystemIdForUser(Windows::System::User const& user)
{
    return impl::call_factory<SystemIdentification, Windows::System::Profile::ISystemIdentificationStatics>([&](auto&& f) { return f.GetSystemIdForUser(user); });
}

inline Windows::System::Profile::SystemOutOfBoxExperienceState SystemSetupInfo::OutOfBoxExperienceState()
{
    return impl::call_factory<SystemSetupInfo, Windows::System::Profile::ISystemSetupInfoStatics>([&](auto&& f) { return f.OutOfBoxExperienceState(); });
}

inline winrt::event_token SystemSetupInfo::OutOfBoxExperienceStateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<SystemSetupInfo, Windows::System::Profile::ISystemSetupInfoStatics>([&](auto&& f) { return f.OutOfBoxExperienceStateChanged(handler); });
}

inline SystemSetupInfo::OutOfBoxExperienceStateChanged_revoker SystemSetupInfo::OutOfBoxExperienceStateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<SystemSetupInfo, Windows::System::Profile::ISystemSetupInfoStatics>();
    return { f, f.OutOfBoxExperienceStateChanged(handler) };
}

inline void SystemSetupInfo::OutOfBoxExperienceStateChanged(winrt::event_token const& token)
{
    impl::call_factory<SystemSetupInfo, Windows::System::Profile::ISystemSetupInfoStatics>([&](auto&& f) { return f.OutOfBoxExperienceStateChanged(token); });
}

inline bool WindowsIntegrityPolicy::IsEnabled()
{
    return impl::call_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>([&](auto&& f) { return f.IsEnabled(); });
}

inline bool WindowsIntegrityPolicy::IsEnabledForTrial()
{
    return impl::call_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>([&](auto&& f) { return f.IsEnabledForTrial(); });
}

inline bool WindowsIntegrityPolicy::CanDisable()
{
    return impl::call_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>([&](auto&& f) { return f.CanDisable(); });
}

inline bool WindowsIntegrityPolicy::IsDisableSupported()
{
    return impl::call_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>([&](auto&& f) { return f.IsDisableSupported(); });
}

inline winrt::event_token WindowsIntegrityPolicy::PolicyChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>([&](auto&& f) { return f.PolicyChanged(handler); });
}

inline WindowsIntegrityPolicy::PolicyChanged_revoker WindowsIntegrityPolicy::PolicyChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>();
    return { f, f.PolicyChanged(handler) };
}

inline void WindowsIntegrityPolicy::PolicyChanged(winrt::event_token const& token)
{
    impl::call_factory<WindowsIntegrityPolicy, Windows::System::Profile::IWindowsIntegrityPolicyStatics>([&](auto&& f) { return f.PolicyChanged(token); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Profile::IAnalyticsInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IAnalyticsInfoStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IAnalyticsInfoStatics2> : winrt::impl::hash_base<winrt::Windows::System::Profile::IAnalyticsInfoStatics2> {};
template<> struct hash<winrt::Windows::System::Profile::IAnalyticsVersionInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::IAnalyticsVersionInfo> {};
template<> struct hash<winrt::Windows::System::Profile::IAppApplicabilityStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IAppApplicabilityStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IEducationSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IEducationSettingsStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IHardwareIdentificationStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IHardwareIdentificationStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IHardwareToken> : winrt::impl::hash_base<winrt::Windows::System::Profile::IHardwareToken> {};
template<> struct hash<winrt::Windows::System::Profile::IKnownRetailInfoPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IKnownRetailInfoPropertiesStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IPlatformDiagnosticsAndUsageDataSettingsStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IRetailInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IRetailInfoStatics> {};
template<> struct hash<winrt::Windows::System::Profile::ISharedModeSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::ISharedModeSettingsStatics> {};
template<> struct hash<winrt::Windows::System::Profile::ISharedModeSettingsStatics2> : winrt::impl::hash_base<winrt::Windows::System::Profile::ISharedModeSettingsStatics2> {};
template<> struct hash<winrt::Windows::System::Profile::ISystemIdentificationInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::ISystemIdentificationInfo> {};
template<> struct hash<winrt::Windows::System::Profile::ISystemIdentificationStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::ISystemIdentificationStatics> {};
template<> struct hash<winrt::Windows::System::Profile::ISystemSetupInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::ISystemSetupInfoStatics> {};
template<> struct hash<winrt::Windows::System::Profile::IUnsupportedAppRequirement> : winrt::impl::hash_base<winrt::Windows::System::Profile::IUnsupportedAppRequirement> {};
template<> struct hash<winrt::Windows::System::Profile::IWindowsIntegrityPolicyStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::IWindowsIntegrityPolicyStatics> {};
template<> struct hash<winrt::Windows::System::Profile::AnalyticsInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::AnalyticsInfo> {};
template<> struct hash<winrt::Windows::System::Profile::AnalyticsVersionInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::AnalyticsVersionInfo> {};
template<> struct hash<winrt::Windows::System::Profile::AppApplicability> : winrt::impl::hash_base<winrt::Windows::System::Profile::AppApplicability> {};
template<> struct hash<winrt::Windows::System::Profile::EducationSettings> : winrt::impl::hash_base<winrt::Windows::System::Profile::EducationSettings> {};
template<> struct hash<winrt::Windows::System::Profile::HardwareIdentification> : winrt::impl::hash_base<winrt::Windows::System::Profile::HardwareIdentification> {};
template<> struct hash<winrt::Windows::System::Profile::HardwareToken> : winrt::impl::hash_base<winrt::Windows::System::Profile::HardwareToken> {};
template<> struct hash<winrt::Windows::System::Profile::KnownRetailInfoProperties> : winrt::impl::hash_base<winrt::Windows::System::Profile::KnownRetailInfoProperties> {};
template<> struct hash<winrt::Windows::System::Profile::PlatformDiagnosticsAndUsageDataSettings> : winrt::impl::hash_base<winrt::Windows::System::Profile::PlatformDiagnosticsAndUsageDataSettings> {};
template<> struct hash<winrt::Windows::System::Profile::RetailInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::RetailInfo> {};
template<> struct hash<winrt::Windows::System::Profile::SharedModeSettings> : winrt::impl::hash_base<winrt::Windows::System::Profile::SharedModeSettings> {};
template<> struct hash<winrt::Windows::System::Profile::SystemIdentification> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemIdentification> {};
template<> struct hash<winrt::Windows::System::Profile::SystemIdentificationInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemIdentificationInfo> {};
template<> struct hash<winrt::Windows::System::Profile::SystemSetupInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemSetupInfo> {};
template<> struct hash<winrt::Windows::System::Profile::UnsupportedAppRequirement> : winrt::impl::hash_base<winrt::Windows::System::Profile::UnsupportedAppRequirement> {};
template<> struct hash<winrt::Windows::System::Profile::WindowsIntegrityPolicy> : winrt::impl::hash_base<winrt::Windows::System::Profile::WindowsIntegrityPolicy> {};

}
