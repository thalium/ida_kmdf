// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Diagnostics.Telemetry.2.h"
#include "winrt/Windows.System.Diagnostics.h"

namespace winrt::impl {

template <typename D> Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryClientStatics<D>::Register(param::hstring const& id) const
{
    Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics)->Register(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryClientStatics<D>::Register(param::hstring const& id, Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const& settings) const
{
    Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics)->RegisterWithSettings(get_abi(id), get_abi(settings), put_abi(result)));
    return result;
}

template <typename D> Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationResult<D>::Status() const
{
    Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::StorageSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->get_StorageSize(&value));
    return value;
}

template <typename D> void consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::StorageSize(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->put_StorageSize(value));
}

template <typename D> uint32_t consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::UploadQuotaSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->get_UploadQuotaSize(&value));
    return value;
}

template <typename D> void consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::UploadQuotaSize(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->put_UploadQuotaSize(value));
}

template <typename D>
struct produce<D, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics> : produce_base<D, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics>
{
    int32_t WINRT_CALL Register(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Register, WINRT_WRAP(Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult), hstring const&);
            *result = detach_from<Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult>(this->shim().Register(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterWithSettings(void* id, void* settings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Register, WINRT_WRAP(Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult), hstring const&, Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const&);
            *result = detach_from<Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult>(this->shim().Register(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult> : produce_base<D, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult>
{
    int32_t WINRT_CALL get_Status(Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus));
            *value = detach_from<Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings> : produce_base<D, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings>
{
    int32_t WINRT_CALL get_StorageSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().StorageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StorageSize(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageSize, WINRT_WRAP(void), uint32_t);
            this->shim().StorageSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UploadQuotaSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UploadQuotaSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UploadQuotaSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UploadQuotaSize(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UploadQuotaSize, WINRT_WRAP(void), uint32_t);
            this->shim().UploadQuotaSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::Telemetry {

inline Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult PlatformTelemetryClient::Register(param::hstring const& id)
{
    return impl::call_factory<PlatformTelemetryClient, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics>([&](auto&& f) { return f.Register(id); });
}

inline Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult PlatformTelemetryClient::Register(param::hstring const& id, Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const& settings)
{
    return impl::call_factory<PlatformTelemetryClient, Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics>([&](auto&& f) { return f.Register(id, settings); });
}

inline PlatformTelemetryRegistrationSettings::PlatformTelemetryRegistrationSettings() :
    PlatformTelemetryRegistrationSettings(impl::call_factory<PlatformTelemetryRegistrationSettings>([](auto&& f) { return f.template ActivateInstance<PlatformTelemetryRegistrationSettings>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics> {};
template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult> {};
template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings> {};
template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryClient> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryClient> {};
template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult> {};
template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings> {};

}
