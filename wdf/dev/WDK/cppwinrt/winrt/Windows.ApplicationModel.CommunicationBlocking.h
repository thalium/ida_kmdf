// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.CommunicationBlocking.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::IsBlockingActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->get_IsBlockingActive(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::IsBlockedNumberAsync(param::hstring const& number) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->IsBlockedNumberAsync(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowBlockNumbersUI(param::iterable<hstring> const& phoneNumbers) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowBlockNumbersUI(get_abi(phoneNumbers), &value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowUnblockNumbersUI(param::iterable<hstring> const& phoneNumbers) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowUnblockNumbersUI(get_abi(phoneNumbers), &value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowBlockedCallsUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowBlockedCallsUI());
}

template <typename D> void consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowBlockedMessagesUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowBlockedMessagesUI());
}

template <typename D> bool consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics<D>::IsCurrentAppActiveBlockingApp() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics)->get_IsCurrentAppActiveBlockingApp(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics<D>::ShowCommunicationBlockingSettingsUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics)->ShowCommunicationBlockingSettingsUI());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics2<D>::RequestSetAsActiveBlockingAppAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2)->RequestSetAsActiveBlockingAppAsync(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics> : produce_base<D, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>
{
    int32_t WINRT_CALL get_IsBlockingActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlockingActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBlockingActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsBlockedNumberAsync(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlockedNumberAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsBlockedNumberAsync(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowBlockNumbersUI(void* phoneNumbers, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowBlockNumbersUI, WINRT_WRAP(bool), Windows::Foundation::Collections::IIterable<hstring> const&);
            *value = detach_from<bool>(this->shim().ShowBlockNumbersUI(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&phoneNumbers)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowUnblockNumbersUI(void* phoneNumbers, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowUnblockNumbersUI, WINRT_WRAP(bool), Windows::Foundation::Collections::IIterable<hstring> const&);
            *value = detach_from<bool>(this->shim().ShowUnblockNumbersUI(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&phoneNumbers)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowBlockedCallsUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowBlockedCallsUI, WINRT_WRAP(void));
            this->shim().ShowBlockedCallsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowBlockedMessagesUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowBlockedMessagesUI, WINRT_WRAP(void));
            this->shim().ShowBlockedMessagesUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics> : produce_base<D, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>
{
    int32_t WINRT_CALL get_IsCurrentAppActiveBlockingApp(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentAppActiveBlockingApp, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCurrentAppActiveBlockingApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowCommunicationBlockingSettingsUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowCommunicationBlockingSettingsUI, WINRT_WRAP(void));
            this->shim().ShowCommunicationBlockingSettingsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2> : produce_base<D, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>
{
    int32_t WINRT_CALL RequestSetAsActiveBlockingAppAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetAsActiveBlockingAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestSetAsActiveBlockingAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::CommunicationBlocking {

inline bool CommunicationBlockingAccessManager::IsBlockingActive()
{
    return impl::call_factory<CommunicationBlockingAccessManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>([&](auto&& f) { return f.IsBlockingActive(); });
}

inline Windows::Foundation::IAsyncOperation<bool> CommunicationBlockingAccessManager::IsBlockedNumberAsync(param::hstring const& number)
{
    return impl::call_factory<CommunicationBlockingAccessManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>([&](auto&& f) { return f.IsBlockedNumberAsync(number); });
}

inline bool CommunicationBlockingAccessManager::ShowBlockNumbersUI(param::iterable<hstring> const& phoneNumbers)
{
    return impl::call_factory<CommunicationBlockingAccessManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>([&](auto&& f) { return f.ShowBlockNumbersUI(phoneNumbers); });
}

inline bool CommunicationBlockingAccessManager::ShowUnblockNumbersUI(param::iterable<hstring> const& phoneNumbers)
{
    return impl::call_factory<CommunicationBlockingAccessManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>([&](auto&& f) { return f.ShowUnblockNumbersUI(phoneNumbers); });
}

inline void CommunicationBlockingAccessManager::ShowBlockedCallsUI()
{
    impl::call_factory<CommunicationBlockingAccessManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>([&](auto&& f) { return f.ShowBlockedCallsUI(); });
}

inline void CommunicationBlockingAccessManager::ShowBlockedMessagesUI()
{
    impl::call_factory<CommunicationBlockingAccessManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>([&](auto&& f) { return f.ShowBlockedMessagesUI(); });
}

inline bool CommunicationBlockingAppManager::IsCurrentAppActiveBlockingApp()
{
    return impl::call_factory<CommunicationBlockingAppManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>([&](auto&& f) { return f.IsCurrentAppActiveBlockingApp(); });
}

inline void CommunicationBlockingAppManager::ShowCommunicationBlockingSettingsUI()
{
    impl::call_factory<CommunicationBlockingAppManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>([&](auto&& f) { return f.ShowCommunicationBlockingSettingsUI(); });
}

inline Windows::Foundation::IAsyncOperation<bool> CommunicationBlockingAppManager::RequestSetAsActiveBlockingAppAsync()
{
    return impl::call_factory<CommunicationBlockingAppManager, Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>([&](auto&& f) { return f.RequestSetAsActiveBlockingAppAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAccessManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAccessManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAppManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAppManager> {};

}
