// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.DataProtection.2.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Deferral consume_Windows_Security_DataProtection_IUserDataAvailabilityStateChangedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Security::DataProtection::UserDataBufferUnprotectStatus consume_Windows_Security_DataProtection_IUserDataBufferUnprotectResult<D>::Status() const
{
    Windows::Security::DataProtection::UserDataBufferUnprotectStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataBufferUnprotectResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_DataProtection_IUserDataBufferUnprotectResult<D>::UnprotectedBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataBufferUnprotectResult)->get_UnprotectedBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::ProtectStorageItemAsync(Windows::Storage::IStorageItem const& storageItem, Windows::Security::DataProtection::UserDataAvailability const& availability) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->ProtectStorageItemAsync(get_abi(storageItem), get_abi(availability), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionInfo> consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::GetStorageItemProtectionInfoAsync(Windows::Storage::IStorageItem const& storageItem) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->GetStorageItemProtectionInfoAsync(get_abi(storageItem), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::ProtectBufferAsync(Windows::Storage::Streams::IBuffer const& unprotectedBuffer, Windows::Security::DataProtection::UserDataAvailability const& availability) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->ProtectBufferAsync(get_abi(unprotectedBuffer), get_abi(availability), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataBufferUnprotectResult> consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::UnprotectBufferAsync(Windows::Storage::Streams::IBuffer const& protectedBuffer) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataBufferUnprotectResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->UnprotectBufferAsync(get_abi(protectedBuffer), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::IsContinuedDataAvailabilityExpected(Windows::Security::DataProtection::UserDataAvailability const& availability) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->IsContinuedDataAvailabilityExpected(get_abi(availability), &value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged(Windows::Foundation::TypedEventHandler<Windows::Security::DataProtection::UserDataProtectionManager, Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->add_DataAvailabilityStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged_revoker consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Security::DataProtection::UserDataProtectionManager, Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DataAvailabilityStateChanged_revoker>(this, DataAvailabilityStateChanged(handler));
}

template <typename D> void consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManager)->remove_DataAvailabilityStateChanged(get_abi(token)));
}

template <typename D> Windows::Security::DataProtection::UserDataProtectionManager consume_Windows_Security_DataProtection_IUserDataProtectionManagerStatics<D>::TryGetDefault() const
{
    Windows::Security::DataProtection::UserDataProtectionManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManagerStatics)->TryGetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Security::DataProtection::UserDataProtectionManager consume_Windows_Security_DataProtection_IUserDataProtectionManagerStatics<D>::TryGetForUser(Windows::System::User const& user) const
{
    Windows::Security::DataProtection::UserDataProtectionManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataProtectionManagerStatics)->TryGetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::DataProtection::UserDataAvailability consume_Windows_Security_DataProtection_IUserDataStorageItemProtectionInfo<D>::Availability() const
{
    Windows::Security::DataProtection::UserDataAvailability value{};
    check_hresult(WINRT_SHIM(Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo)->get_Availability(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs> : produce_base<D, Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::DataProtection::IUserDataBufferUnprotectResult> : produce_base<D, Windows::Security::DataProtection::IUserDataBufferUnprotectResult>
{
    int32_t WINRT_CALL get_Status(Windows::Security::DataProtection::UserDataBufferUnprotectStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::DataProtection::UserDataBufferUnprotectStatus));
            *value = detach_from<Windows::Security::DataProtection::UserDataBufferUnprotectStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnprotectedBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprotectedBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().UnprotectedBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::DataProtection::IUserDataProtectionManager> : produce_base<D, Windows::Security::DataProtection::IUserDataProtectionManager>
{
    int32_t WINRT_CALL ProtectStorageItemAsync(void* storageItem, Windows::Security::DataProtection::UserDataAvailability availability, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectStorageItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>), Windows::Storage::IStorageItem const, Windows::Security::DataProtection::UserDataAvailability const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>>(this->shim().ProtectStorageItemAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&storageItem), *reinterpret_cast<Windows::Security::DataProtection::UserDataAvailability const*>(&availability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStorageItemProtectionInfoAsync(void* storageItem, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStorageItemProtectionInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionInfo>), Windows::Storage::IStorageItem const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataStorageItemProtectionInfo>>(this->shim().GetStorageItemProtectionInfoAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&storageItem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProtectBufferAsync(void* unprotectedBuffer, Windows::Security::DataProtection::UserDataAvailability availability, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Storage::Streams::IBuffer const, Windows::Security::DataProtection::UserDataAvailability const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().ProtectBufferAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&unprotectedBuffer), *reinterpret_cast<Windows::Security::DataProtection::UserDataAvailability const*>(&availability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprotectBufferAsync(void* protectedBuffer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprotectBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataBufferUnprotectResult>), Windows::Storage::Streams::IBuffer const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::DataProtection::UserDataBufferUnprotectResult>>(this->shim().UnprotectBufferAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&protectedBuffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsContinuedDataAvailabilityExpected(Windows::Security::DataProtection::UserDataAvailability availability, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContinuedDataAvailabilityExpected, WINRT_WRAP(bool), Windows::Security::DataProtection::UserDataAvailability const&);
            *value = detach_from<bool>(this->shim().IsContinuedDataAvailabilityExpected(*reinterpret_cast<Windows::Security::DataProtection::UserDataAvailability const*>(&availability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DataAvailabilityStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataAvailabilityStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Security::DataProtection::UserDataProtectionManager, Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DataAvailabilityStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Security::DataProtection::UserDataProtectionManager, Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataAvailabilityStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataAvailabilityStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataAvailabilityStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Security::DataProtection::IUserDataProtectionManagerStatics> : produce_base<D, Windows::Security::DataProtection::IUserDataProtectionManagerStatics>
{
    int32_t WINRT_CALL TryGetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetDefault, WINRT_WRAP(Windows::Security::DataProtection::UserDataProtectionManager));
            *result = detach_from<Windows::Security::DataProtection::UserDataProtectionManager>(this->shim().TryGetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetForUser, WINRT_WRAP(Windows::Security::DataProtection::UserDataProtectionManager), Windows::System::User const&);
            *result = detach_from<Windows::Security::DataProtection::UserDataProtectionManager>(this->shim().TryGetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo> : produce_base<D, Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo>
{
    int32_t WINRT_CALL get_Availability(Windows::Security::DataProtection::UserDataAvailability* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Availability, WINRT_WRAP(Windows::Security::DataProtection::UserDataAvailability));
            *value = detach_from<Windows::Security::DataProtection::UserDataAvailability>(this->shim().Availability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::DataProtection {

inline Windows::Security::DataProtection::UserDataProtectionManager UserDataProtectionManager::TryGetDefault()
{
    return impl::call_factory<UserDataProtectionManager, Windows::Security::DataProtection::IUserDataProtectionManagerStatics>([&](auto&& f) { return f.TryGetDefault(); });
}

inline Windows::Security::DataProtection::UserDataProtectionManager UserDataProtectionManager::TryGetForUser(Windows::System::User const& user)
{
    return impl::call_factory<UserDataProtectionManager, Windows::Security::DataProtection::IUserDataProtectionManagerStatics>([&](auto&& f) { return f.TryGetForUser(user); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult> {};
template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataProtectionManager> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::IUserDataProtectionManager> {};
template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics> {};
template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo> {};
template<> struct hash<winrt::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectResult> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectResult> {};
template<> struct hash<winrt::Windows::Security::DataProtection::UserDataProtectionManager> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::UserDataProtectionManager> {};
template<> struct hash<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo> : winrt::impl::hash_base<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo> {};

}
