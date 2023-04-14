// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.Provider.2.h"
#include "winrt/Windows.ApplicationModel.Calls.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin<D>::Category() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin)->get_Category(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin<D>::Category(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin)->put_Category(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin<D>::CategoryDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin)->get_CategoryDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin<D>::CategoryDescription(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin)->put_CategoryDescription(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin<D>::Location() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin<D>::Location(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin)->put_Location(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin2<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin2<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2)->put_DisplayName(get_abi(value)));
}

template <typename D> Windows::Storage::StorageFile consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin3<D>::DisplayPicture() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3)->get_DisplayPicture(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOrigin3<D>::DisplayPicture(Windows::Storage::StorageFile const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3)->put_DisplayPicture(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOriginManagerStatics<D>::IsCurrentAppActiveCallOriginApp() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics)->get_IsCurrentAppActiveCallOriginApp(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOriginManagerStatics<D>::ShowPhoneCallOriginSettingsUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics)->ShowPhoneCallOriginSettingsUI());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOriginManagerStatics<D>::SetCallOrigin(winrt::guid const& requestId, Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin const& callOrigin) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics)->SetCallOrigin(get_abi(requestId), get_abi(callOrigin)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOriginManagerStatics2<D>::RequestSetAsActiveCallOriginAppAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2)->RequestSetAsActiveCallOriginAppAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_Provider_IPhoneCallOriginManagerStatics3<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics3)->get_IsSupported(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin> : produce_base<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin>
{
    int32_t WINRT_CALL get_Category(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Category(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(void), hstring const&);
            this->shim().Category(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CategoryDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CategoryDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CategoryDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CategoryDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CategoryDescription, WINRT_WRAP(void), hstring const&);
            this->shim().CategoryDescription(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), hstring const&);
            this->shim().Location(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2> : produce_base<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2>
{
    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3> : produce_base<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3>
{
    int32_t WINRT_CALL get_DisplayPicture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayPicture, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().DisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayPicture(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayPicture, WINRT_WRAP(void), Windows::Storage::StorageFile const&);
            this->shim().DisplayPicture(*reinterpret_cast<Windows::Storage::StorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics> : produce_base<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics>
{
    int32_t WINRT_CALL get_IsCurrentAppActiveCallOriginApp(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentAppActiveCallOriginApp, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCurrentAppActiveCallOriginApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowPhoneCallOriginSettingsUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowPhoneCallOriginSettingsUI, WINRT_WRAP(void));
            this->shim().ShowPhoneCallOriginSettingsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCallOrigin(winrt::guid requestId, void* callOrigin) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCallOrigin, WINRT_WRAP(void), winrt::guid const&, Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin const&);
            this->shim().SetCallOrigin(*reinterpret_cast<winrt::guid const*>(&requestId), *reinterpret_cast<Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin const*>(&callOrigin));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2> : produce_base<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2>
{
    int32_t WINRT_CALL RequestSetAsActiveCallOriginAppAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetAsActiveCallOriginAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestSetAsActiveCallOriginAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics3> : produce_base<D, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics3>
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
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Provider {

inline PhoneCallOrigin::PhoneCallOrigin() :
    PhoneCallOrigin(impl::call_factory<PhoneCallOrigin>([](auto&& f) { return f.template ActivateInstance<PhoneCallOrigin>(); }))
{}

inline bool PhoneCallOriginManager::IsCurrentAppActiveCallOriginApp()
{
    return impl::call_factory<PhoneCallOriginManager, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics>([&](auto&& f) { return f.IsCurrentAppActiveCallOriginApp(); });
}

inline void PhoneCallOriginManager::ShowPhoneCallOriginSettingsUI()
{
    impl::call_factory<PhoneCallOriginManager, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics>([&](auto&& f) { return f.ShowPhoneCallOriginSettingsUI(); });
}

inline void PhoneCallOriginManager::SetCallOrigin(winrt::guid const& requestId, Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin const& callOrigin)
{
    impl::call_factory<PhoneCallOriginManager, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics>([&](auto&& f) { return f.SetCallOrigin(requestId, callOrigin); });
}

inline Windows::Foundation::IAsyncOperation<bool> PhoneCallOriginManager::RequestSetAsActiveCallOriginAppAsync()
{
    return impl::call_factory<PhoneCallOriginManager, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2>([&](auto&& f) { return f.RequestSetAsActiveCallOriginAppAsync(); });
}

inline bool PhoneCallOriginManager::IsSupported()
{
    return impl::call_factory<PhoneCallOriginManager, Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics3>([&](auto&& f) { return f.IsSupported(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Provider::PhoneCallOriginManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Provider::PhoneCallOriginManager> {};

}
