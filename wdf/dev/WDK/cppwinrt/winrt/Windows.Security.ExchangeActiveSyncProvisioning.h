// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Security.ExchangeActiveSyncProvisioning.2.h"

namespace winrt::impl {

template <typename D> winrt::guid consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation<D>::Id() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation<D>::OperatingSystem() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation)->get_OperatingSystem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation<D>::SystemManufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation)->get_SystemManufacturer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation<D>::SystemProductName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation)->get_SystemProductName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation<D>::SystemSku() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation)->get_SystemSku(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation2<D>::SystemHardwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation2)->get_SystemHardwareVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientDeviceInformation2<D>::SystemFirmwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation2)->get_SystemFirmwareVersion(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::RequireEncryption() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_RequireEncryption(&value));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::RequireEncryption(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_RequireEncryption(value));
}

template <typename D> uint8_t consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MinPasswordLength() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_MinPasswordLength(&value));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MinPasswordLength(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_MinPasswordLength(value));
}

template <typename D> bool consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::DisallowConvenienceLogon() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_DisallowConvenienceLogon(&value));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::DisallowConvenienceLogon(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_DisallowConvenienceLogon(value));
}

template <typename D> uint8_t consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MinPasswordComplexCharacters() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_MinPasswordComplexCharacters(&value));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MinPasswordComplexCharacters(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_MinPasswordComplexCharacters(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::PasswordExpiration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_PasswordExpiration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::PasswordExpiration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_PasswordExpiration(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::PasswordHistory() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_PasswordHistory(&value));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::PasswordHistory(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_PasswordHistory(value));
}

template <typename D> uint8_t consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MaxPasswordFailedAttempts() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_MaxPasswordFailedAttempts(&value));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MaxPasswordFailedAttempts(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_MaxPasswordFailedAttempts(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MaxInactivityTimeLock() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->get_MaxInactivityTimeLock(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::MaxInactivityTimeLock(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->put_MaxInactivityTimeLock(get_abi(value)));
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::CheckCompliance() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->CheckCompliance(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults> consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasClientSecurityPolicy<D>::ApplyAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy)->ApplyAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::Compliant() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_Compliant(&value));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasRequireEncryptionResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::RequireEncryptionResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasRequireEncryptionResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_RequireEncryptionResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordLengthResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::MinPasswordLengthResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordLengthResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_MinPasswordLengthResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasDisallowConvenienceLogonResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::DisallowConvenienceLogonResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasDisallowConvenienceLogonResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_DisallowConvenienceLogonResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordComplexCharactersResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::MinPasswordComplexCharactersResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordComplexCharactersResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_MinPasswordComplexCharactersResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordExpirationResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::PasswordExpirationResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordExpirationResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_PasswordExpirationResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordHistoryResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::PasswordHistoryResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordHistoryResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_PasswordHistoryResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasMaxPasswordFailedAttemptsResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::MaxPasswordFailedAttemptsResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasMaxPasswordFailedAttemptsResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_MaxPasswordFailedAttemptsResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasMaxInactivityTimeLockResult consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults<D>::MaxInactivityTimeLockResult() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasMaxInactivityTimeLockResult value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults)->get_MaxInactivityTimeLockResult(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::ExchangeActiveSyncProvisioning::EasEncryptionProviderType consume_Windows_Security_ExchangeActiveSyncProvisioning_IEasComplianceResults2<D>::EncryptionProviderType() const
{
    Windows::Security::ExchangeActiveSyncProvisioning::EasEncryptionProviderType value{};
    check_hresult(WINRT_SHIM(Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults2)->get_EncryptionProviderType(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation> : produce_base<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation>
{
    int32_t WINRT_CALL get_Id(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OperatingSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperatingSystem, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OperatingSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemManufacturer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemManufacturer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemManufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemProductName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemProductName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemProductName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemSku(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSku, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemSku());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation2> : produce_base<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation2>
{
    int32_t WINRT_CALL get_SystemHardwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemHardwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemHardwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemFirmwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemFirmwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemFirmwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy> : produce_base<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy>
{
    int32_t WINRT_CALL get_RequireEncryption(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequireEncryption, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RequireEncryption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequireEncryption(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequireEncryption, WINRT_WRAP(void), bool);
            this->shim().RequireEncryption(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPasswordLength(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPasswordLength, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().MinPasswordLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinPasswordLength(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPasswordLength, WINRT_WRAP(void), uint8_t);
            this->shim().MinPasswordLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisallowConvenienceLogon(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisallowConvenienceLogon, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DisallowConvenienceLogon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisallowConvenienceLogon(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisallowConvenienceLogon, WINRT_WRAP(void), bool);
            this->shim().DisallowConvenienceLogon(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPasswordComplexCharacters(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPasswordComplexCharacters, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().MinPasswordComplexCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinPasswordComplexCharacters(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPasswordComplexCharacters, WINRT_WRAP(void), uint8_t);
            this->shim().MinPasswordComplexCharacters(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PasswordExpiration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordExpiration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().PasswordExpiration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PasswordExpiration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordExpiration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().PasswordExpiration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PasswordHistory(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordHistory, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PasswordHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PasswordHistory(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordHistory, WINRT_WRAP(void), uint32_t);
            this->shim().PasswordHistory(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPasswordFailedAttempts(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPasswordFailedAttempts, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().MaxPasswordFailedAttempts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPasswordFailedAttempts(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPasswordFailedAttempts, WINRT_WRAP(void), uint8_t);
            this->shim().MaxPasswordFailedAttempts(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxInactivityTimeLock(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxInactivityTimeLock, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MaxInactivityTimeLock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxInactivityTimeLock(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxInactivityTimeLock, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().MaxInactivityTimeLock(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckCompliance(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckCompliance, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults));
            *result = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults>(this->shim().CheckCompliance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults>>(this->shim().ApplyAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults> : produce_base<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults>
{
    int32_t WINRT_CALL get_Compliant(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compliant, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Compliant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequireEncryptionResult(Windows::Security::ExchangeActiveSyncProvisioning::EasRequireEncryptionResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequireEncryptionResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasRequireEncryptionResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasRequireEncryptionResult>(this->shim().RequireEncryptionResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPasswordLengthResult(Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordLengthResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPasswordLengthResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordLengthResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordLengthResult>(this->shim().MinPasswordLengthResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisallowConvenienceLogonResult(Windows::Security::ExchangeActiveSyncProvisioning::EasDisallowConvenienceLogonResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisallowConvenienceLogonResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasDisallowConvenienceLogonResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasDisallowConvenienceLogonResult>(this->shim().DisallowConvenienceLogonResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPasswordComplexCharactersResult(Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordComplexCharactersResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPasswordComplexCharactersResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordComplexCharactersResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasMinPasswordComplexCharactersResult>(this->shim().MinPasswordComplexCharactersResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PasswordExpirationResult(Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordExpirationResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordExpirationResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordExpirationResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordExpirationResult>(this->shim().PasswordExpirationResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PasswordHistoryResult(Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordHistoryResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordHistoryResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordHistoryResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasPasswordHistoryResult>(this->shim().PasswordHistoryResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPasswordFailedAttemptsResult(Windows::Security::ExchangeActiveSyncProvisioning::EasMaxPasswordFailedAttemptsResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPasswordFailedAttemptsResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasMaxPasswordFailedAttemptsResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasMaxPasswordFailedAttemptsResult>(this->shim().MaxPasswordFailedAttemptsResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxInactivityTimeLockResult(Windows::Security::ExchangeActiveSyncProvisioning::EasMaxInactivityTimeLockResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxInactivityTimeLockResult, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasMaxInactivityTimeLockResult));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasMaxInactivityTimeLockResult>(this->shim().MaxInactivityTimeLockResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults2> : produce_base<D, Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults2>
{
    int32_t WINRT_CALL get_EncryptionProviderType(Windows::Security::ExchangeActiveSyncProvisioning::EasEncryptionProviderType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncryptionProviderType, WINRT_WRAP(Windows::Security::ExchangeActiveSyncProvisioning::EasEncryptionProviderType));
            *value = detach_from<Windows::Security::ExchangeActiveSyncProvisioning::EasEncryptionProviderType>(this->shim().EncryptionProviderType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::ExchangeActiveSyncProvisioning {

inline EasClientDeviceInformation::EasClientDeviceInformation() :
    EasClientDeviceInformation(impl::call_factory<EasClientDeviceInformation>([](auto&& f) { return f.template ActivateInstance<EasClientDeviceInformation>(); }))
{}

inline EasClientSecurityPolicy::EasClientSecurityPolicy() :
    EasClientSecurityPolicy(impl::call_factory<EasClientSecurityPolicy>([](auto&& f) { return f.template ActivateInstance<EasClientSecurityPolicy>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation2> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasClientDeviceInformation2> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasClientSecurityPolicy> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults2> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::IEasComplianceResults2> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::EasClientDeviceInformation> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::EasClientDeviceInformation> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::EasClientSecurityPolicy> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::EasClientSecurityPolicy> {};
template<> struct hash<winrt::Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults> : winrt::impl::hash_base<winrt::Windows::Security::ExchangeActiveSyncProvisioning::EasComplianceResults> {};

}
