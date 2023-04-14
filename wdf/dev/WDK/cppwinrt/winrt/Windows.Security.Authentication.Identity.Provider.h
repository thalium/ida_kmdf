// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.Authentication.Identity.Provider.2.h"
#include "winrt/Windows.Security.Authentication.Identity.h"

namespace winrt::impl {

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthentication<D>::ServiceAuthenticationHmac() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication)->get_ServiceAuthenticationHmac(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthentication<D>::SessionNonce() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication)->get_SessionNonce(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthentication<D>::DeviceNonce() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication)->get_DeviceNonce(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthentication<D>::DeviceConfigurationData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication)->get_DeviceConfigurationData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorFinishAuthenticationStatus> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthentication<D>::FinishAuthenticationAsync(Windows::Storage::Streams::IBuffer const& deviceHmac, Windows::Storage::Streams::IBuffer const& sessionHmac) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorFinishAuthenticationStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication)->FinishAuthenticationAsync(get_abi(deviceHmac), get_abi(sessionHmac), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthentication<D>::AbortAuthenticationAsync(param::hstring const& errorLogMessage) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication)->AbortAuthenticationAsync(get_abi(errorLogMessage), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStatus consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationResult<D>::Status() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthentication consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationResult<D>::Authentication() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthentication value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult)->get_Authentication(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs<D>::StageInfo() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs)->get_StageInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStage consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStageInfo<D>::Stage() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStage value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo)->get_Stage(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationScenario consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStageInfo<D>::Scenario() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationScenario value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo)->get_Scenario(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStageInfo<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::ShowNotificationMessageAsync(param::hstring const& deviceName, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationMessage const& message) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics)->ShowNotificationMessageAsync(get_abi(deviceName), get_abi(message), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::StartAuthenticationAsync(param::hstring const& deviceId, Windows::Storage::Streams::IBuffer const& serviceAuthenticationNonce) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics)->StartAuthenticationAsync(get_abi(deviceId), get_abi(serviceAuthenticationNonce), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::AuthenticationStageChanged(Windows::Foundation::EventHandler<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics)->add_AuthenticationStageChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::AuthenticationStageChanged_revoker consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::AuthenticationStageChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AuthenticationStageChanged_revoker>(this, AuthenticationStageChanged(handler));
}

template <typename D> void consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::AuthenticationStageChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics)->remove_AuthenticationStageChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorAuthenticationStatics<D>::GetAuthenticationStageInfoAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics)->GetAuthenticationStageInfoAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics<D>::RegisterDevicePresenceMonitoringAsync(param::hstring const& deviceId, param::hstring const& deviceInstancePath, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const& monitoringMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics)->RegisterDevicePresenceMonitoringAsync(get_abi(deviceId), get_abi(deviceInstancePath), get_abi(monitoringMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics<D>::RegisterDevicePresenceMonitoringAsync(param::hstring const& deviceId, param::hstring const& deviceInstancePath, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const& monitoringMode, param::hstring const& deviceFriendlyName, param::hstring const& deviceModelNumber, Windows::Storage::Streams::IBuffer const& deviceConfigurationData) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics)->RegisterDevicePresenceMonitoringWithNewDeviceAsync(get_abi(deviceId), get_abi(deviceInstancePath), get_abi(monitoringMode), get_abi(deviceFriendlyName), get_abi(deviceModelNumber), get_abi(deviceConfigurationData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics<D>::UnregisterDevicePresenceMonitoringAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics)->UnregisterDevicePresenceMonitoringAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics<D>::IsDevicePresenceMonitoringSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics)->IsDevicePresenceMonitoringSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo<D>::DeviceId() const
{
    hstring deviceId{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo)->get_DeviceId(put_abi(deviceId)));
    return deviceId;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo<D>::DeviceFriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo)->get_DeviceFriendlyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo<D>::DeviceModelNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo)->get_DeviceModelNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo<D>::DeviceConfigurationData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo)->get_DeviceConfigurationData(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo2<D>::PresenceMonitoringMode() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2)->get_PresenceMonitoringMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo2<D>::UpdateDevicePresenceAsync(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresence const& presenceState) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2)->UpdateDevicePresenceAsync(get_abi(presenceState), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorInfo2<D>::IsAuthenticationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2)->get_IsAuthenticationSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistration<D>::FinishRegisteringDeviceAsync(Windows::Storage::Streams::IBuffer const& deviceConfigurationData) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration)->FinishRegisteringDeviceAsync(get_abi(deviceConfigurationData), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistration<D>::AbortRegisteringDeviceAsync(param::hstring const& errorLogMessage) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration)->AbortRegisteringDeviceAsync(get_abi(errorLogMessage), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationStatus consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistrationResult<D>::Status() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistration consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistrationResult<D>::Registration() const
{
    Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult)->get_Registration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistrationStatics<D>::RequestStartRegisteringDeviceAsync(param::hstring const& deviceId, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceCapabilities const& capabilities, param::hstring const& deviceFriendlyName, param::hstring const& deviceModelNumber, Windows::Storage::Streams::IBuffer const& deviceKey, Windows::Storage::Streams::IBuffer const& mutualAuthenticationKey) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics)->RequestStartRegisteringDeviceAsync(get_abi(deviceId), get_abi(capabilities), get_abi(deviceFriendlyName), get_abi(deviceModelNumber), get_abi(deviceKey), get_abi(mutualAuthenticationKey), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo>> consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistrationStatics<D>::FindAllRegisteredDeviceInfoAsync(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceFindScope const& queryType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo>> deviceInfoList{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics)->FindAllRegisteredDeviceInfoAsync(get_abi(queryType), put_abi(deviceInfoList)));
    return deviceInfoList;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistrationStatics<D>::UnregisterDeviceAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics)->UnregisterDeviceAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Identity_Provider_ISecondaryAuthenticationFactorRegistrationStatics<D>::UpdateDeviceConfigurationDataAsync(param::hstring const& deviceId, Windows::Storage::Streams::IBuffer const& deviceConfigurationData) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics)->UpdateDeviceConfigurationDataAsync(get_abi(deviceId), get_abi(deviceConfigurationData), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication>
{
    int32_t WINRT_CALL get_ServiceAuthenticationHmac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceAuthenticationHmac, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ServiceAuthenticationHmac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionNonce(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionNonce, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SessionNonce());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceNonce(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceNonce, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DeviceNonce());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceConfigurationData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceConfigurationData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DeviceConfigurationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FinishAuthenticationAsync(void* deviceHmac, void* sessionHmac, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAuthenticationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorFinishAuthenticationStatus>), Windows::Storage::Streams::IBuffer const, Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorFinishAuthenticationStatus>>(this->shim().FinishAuthenticationAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&deviceHmac), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&sessionHmac)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AbortAuthenticationAsync(void* errorLogMessage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbortAuthenticationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AbortAuthenticationAsync(*reinterpret_cast<hstring const*>(&errorLogMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStatus));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Authentication(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Authentication, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthentication));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthentication>(this->shim().Authentication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs>
{
    int32_t WINRT_CALL get_StageInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageInfo, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo>(this->shim().StageInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo>
{
    int32_t WINRT_CALL get_Stage(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStage* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stage, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStage));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStage>(this->shim().Stage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scenario(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationScenario* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scenario, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationScenario));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationScenario>(this->shim().Scenario());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>
{
    int32_t WINRT_CALL ShowNotificationMessageAsync(void* deviceName, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationMessage message, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNotificationMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationMessage const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowNotificationMessageAsync(*reinterpret_cast<hstring const*>(&deviceName), *reinterpret_cast<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAuthenticationAsync(void* deviceId, void* serviceAuthenticationNonce, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAuthenticationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult>), hstring const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult>>(this->shim().StartAuthenticationAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&serviceAuthenticationNonce)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AuthenticationStageChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationStageChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AuthenticationStageChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AuthenticationStageChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AuthenticationStageChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AuthenticationStageChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetAuthenticationStageInfoAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAuthenticationStageInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo>>(this->shim().GetAuthenticationStageInfoAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics>
{
    int32_t WINRT_CALL RegisterDevicePresenceMonitoringAsync(void* deviceId, void* deviceInstancePath, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode monitoringMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterDevicePresenceMonitoringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus>), hstring const, hstring const, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus>>(this->shim().RegisterDevicePresenceMonitoringAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<hstring const*>(&deviceInstancePath), *reinterpret_cast<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const*>(&monitoringMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterDevicePresenceMonitoringWithNewDeviceAsync(void* deviceId, void* deviceInstancePath, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode monitoringMode, void* deviceFriendlyName, void* deviceModelNumber, void* deviceConfigurationData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterDevicePresenceMonitoringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus>), hstring const, hstring const, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const, hstring const, hstring const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus>>(this->shim().RegisterDevicePresenceMonitoringAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<hstring const*>(&deviceInstancePath), *reinterpret_cast<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const*>(&monitoringMode), *reinterpret_cast<hstring const*>(&deviceFriendlyName), *reinterpret_cast<hstring const*>(&deviceModelNumber), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&deviceConfigurationData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterDevicePresenceMonitoringAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterDevicePresenceMonitoringAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnregisterDevicePresenceMonitoringAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsDevicePresenceMonitoringSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDevicePresenceMonitoringSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDevicePresenceMonitoringSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo>
{
    int32_t WINRT_CALL get_DeviceId(void** deviceId) noexcept final
    {
        try
        {
            *deviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *deviceId = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceFriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceFriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceModelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceModelNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceConfigurationData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceConfigurationData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DeviceConfigurationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2>
{
    int32_t WINRT_CALL get_PresenceMonitoringMode(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresenceMonitoringMode, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode>(this->shim().PresenceMonitoringMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateDevicePresenceAsync(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresence presenceState, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateDevicePresenceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresence const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateDevicePresenceAsync(*reinterpret_cast<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresence const*>(&presenceState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAuthenticationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAuthenticationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAuthenticationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration>
{
    int32_t WINRT_CALL FinishRegisteringDeviceAsync(void* deviceConfigurationData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishRegisteringDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FinishRegisteringDeviceAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&deviceConfigurationData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AbortRegisteringDeviceAsync(void* errorLogMessage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbortRegisteringDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AbortRegisteringDeviceAsync(*reinterpret_cast<hstring const*>(&errorLogMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationStatus));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Registration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Registration, WINRT_WRAP(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistration));
            *value = detach_from<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistration>(this->shim().Registration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics> : produce_base<D, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics>
{
    int32_t WINRT_CALL RequestStartRegisteringDeviceAsync(void* deviceId, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceCapabilities capabilities, void* deviceFriendlyName, void* deviceModelNumber, void* deviceKey, void* mutualAuthenticationKey, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStartRegisteringDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult>), hstring const, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceCapabilities const, hstring const, hstring const, Windows::Storage::Streams::IBuffer const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult>>(this->shim().RequestStartRegisteringDeviceAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceCapabilities const*>(&capabilities), *reinterpret_cast<hstring const*>(&deviceFriendlyName), *reinterpret_cast<hstring const*>(&deviceModelNumber), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&deviceKey), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&mutualAuthenticationKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllRegisteredDeviceInfoAsync(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceFindScope queryType, void** deviceInfoList) noexcept final
    {
        try
        {
            *deviceInfoList = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllRegisteredDeviceInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo>>), Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceFindScope const);
            *deviceInfoList = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo>>>(this->shim().FindAllRegisteredDeviceInfoAsync(*reinterpret_cast<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceFindScope const*>(&queryType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterDeviceAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnregisterDeviceAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateDeviceConfigurationDataAsync(void* deviceId, void* deviceConfigurationData, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateDeviceConfigurationDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateDeviceConfigurationDataAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&deviceConfigurationData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity::Provider {

inline Windows::Foundation::IAsyncAction SecondaryAuthenticationFactorAuthentication::ShowNotificationMessageAsync(param::hstring const& deviceName, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationMessage const& message)
{
    return impl::call_factory<SecondaryAuthenticationFactorAuthentication, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>([&](auto&& f) { return f.ShowNotificationMessageAsync(deviceName, message); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult> SecondaryAuthenticationFactorAuthentication::StartAuthenticationAsync(param::hstring const& deviceId, Windows::Storage::Streams::IBuffer const& serviceAuthenticationNonce)
{
    return impl::call_factory<SecondaryAuthenticationFactorAuthentication, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>([&](auto&& f) { return f.StartAuthenticationAsync(deviceId, serviceAuthenticationNonce); });
}

inline winrt::event_token SecondaryAuthenticationFactorAuthentication::AuthenticationStageChanged(Windows::Foundation::EventHandler<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const& handler)
{
    return impl::call_factory<SecondaryAuthenticationFactorAuthentication, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>([&](auto&& f) { return f.AuthenticationStageChanged(handler); });
}

inline SecondaryAuthenticationFactorAuthentication::AuthenticationStageChanged_revoker SecondaryAuthenticationFactorAuthentication::AuthenticationStageChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const& handler)
{
    auto f = get_activation_factory<SecondaryAuthenticationFactorAuthentication, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>();
    return { f, f.AuthenticationStageChanged(handler) };
}

inline void SecondaryAuthenticationFactorAuthentication::AuthenticationStageChanged(winrt::event_token const& token)
{
    impl::call_factory<SecondaryAuthenticationFactorAuthentication, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>([&](auto&& f) { return f.AuthenticationStageChanged(token); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo> SecondaryAuthenticationFactorAuthentication::GetAuthenticationStageInfoAsync()
{
    return impl::call_factory<SecondaryAuthenticationFactorAuthentication, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>([&](auto&& f) { return f.GetAuthenticationStageInfoAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus> SecondaryAuthenticationFactorRegistration::RegisterDevicePresenceMonitoringAsync(param::hstring const& deviceId, param::hstring const& deviceInstancePath, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const& monitoringMode)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics>([&](auto&& f) { return f.RegisterDevicePresenceMonitoringAsync(deviceId, deviceInstancePath, monitoringMode); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatus> SecondaryAuthenticationFactorRegistration::RegisterDevicePresenceMonitoringAsync(param::hstring const& deviceId, param::hstring const& deviceInstancePath, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const& monitoringMode, param::hstring const& deviceFriendlyName, param::hstring const& deviceModelNumber, Windows::Storage::Streams::IBuffer const& deviceConfigurationData)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics>([&](auto&& f) { return f.RegisterDevicePresenceMonitoringAsync(deviceId, deviceInstancePath, monitoringMode, deviceFriendlyName, deviceModelNumber, deviceConfigurationData); });
}

inline Windows::Foundation::IAsyncAction SecondaryAuthenticationFactorRegistration::UnregisterDevicePresenceMonitoringAsync(param::hstring const& deviceId)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics>([&](auto&& f) { return f.UnregisterDevicePresenceMonitoringAsync(deviceId); });
}

inline bool SecondaryAuthenticationFactorRegistration::IsDevicePresenceMonitoringSupported()
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics>([&](auto&& f) { return f.IsDevicePresenceMonitoringSupported(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult> SecondaryAuthenticationFactorRegistration::RequestStartRegisteringDeviceAsync(param::hstring const& deviceId, Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceCapabilities const& capabilities, param::hstring const& deviceFriendlyName, param::hstring const& deviceModelNumber, Windows::Storage::Streams::IBuffer const& deviceKey, Windows::Storage::Streams::IBuffer const& mutualAuthenticationKey)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics>([&](auto&& f) { return f.RequestStartRegisteringDeviceAsync(deviceId, capabilities, deviceFriendlyName, deviceModelNumber, deviceKey, mutualAuthenticationKey); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo>> SecondaryAuthenticationFactorRegistration::FindAllRegisteredDeviceInfoAsync(Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceFindScope const& queryType)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics>([&](auto&& f) { return f.FindAllRegisteredDeviceInfoAsync(queryType); });
}

inline Windows::Foundation::IAsyncAction SecondaryAuthenticationFactorRegistration::UnregisterDeviceAsync(param::hstring const& deviceId)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics>([&](auto&& f) { return f.UnregisterDeviceAsync(deviceId); });
}

inline Windows::Foundation::IAsyncAction SecondaryAuthenticationFactorRegistration::UpdateDeviceConfigurationDataAsync(param::hstring const& deviceId, Windows::Storage::Streams::IBuffer const& deviceConfigurationData)
{
    return impl::call_factory<SecondaryAuthenticationFactorRegistration, Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics>([&](auto&& f) { return f.UpdateDeviceConfigurationDataAsync(deviceId, deviceConfigurationData); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthentication> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthentication> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageInfo> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorInfo> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistration> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistration> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorRegistrationResult> {};

}
