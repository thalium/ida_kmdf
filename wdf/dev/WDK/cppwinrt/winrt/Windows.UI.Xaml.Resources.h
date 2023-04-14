// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Xaml.Resources.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::Resources::CustomXamlResourceLoader consume_Windows_UI_Xaml_Resources_ICustomXamlResourceLoaderFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Resources::CustomXamlResourceLoader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Resources_ICustomXamlResourceLoaderOverrides<D>::GetResource(param::hstring const& resourceId, param::hstring const& objectType, param::hstring const& propertyName, param::hstring const& propertyType) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides)->GetResource(get_abi(resourceId), get_abi(objectType), get_abi(propertyName), get_abi(propertyType), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Resources::CustomXamlResourceLoader consume_Windows_UI_Xaml_Resources_ICustomXamlResourceLoaderStatics<D>::Current() const
{
    Windows::UI::Xaml::Resources::CustomXamlResourceLoader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Resources_ICustomXamlResourceLoaderStatics<D>::Current(Windows::UI::Xaml::Resources::CustomXamlResourceLoader const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics)->put_Current(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoader> : produce_base<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoader>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory> : produce_base<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Resources::CustomXamlResourceLoader), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Resources::CustomXamlResourceLoader>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides> : produce_base<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides>
{
    int32_t WINRT_CALL GetResource(void* resourceId, void* objectType, void* propertyName, void* propertyType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetResource, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&, hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetResource(*reinterpret_cast<hstring const*>(&resourceId), *reinterpret_cast<hstring const*>(&objectType), *reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<hstring const*>(&propertyType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics> : produce_base<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::UI::Xaml::Resources::CustomXamlResourceLoader));
            *value = detach_from<Windows::UI::Xaml::Resources::CustomXamlResourceLoader>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Current(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(void), Windows::UI::Xaml::Resources::CustomXamlResourceLoader const&);
            this->shim().Current(*reinterpret_cast<Windows::UI::Xaml::Resources::CustomXamlResourceLoader const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides>
{
    Windows::Foundation::IInspectable GetResource(hstring const& resourceId, hstring const& objectType, hstring const& propertyName, hstring const& propertyType)
    {
        Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetResource(resourceId, objectType, propertyName, propertyType);
        }
        return this->shim().GetResource(resourceId, objectType, propertyName, propertyType);
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Resources {

inline CustomXamlResourceLoader::CustomXamlResourceLoader()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CustomXamlResourceLoader, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Resources::CustomXamlResourceLoader CustomXamlResourceLoader::Current()
{
    return impl::call_factory<CustomXamlResourceLoader, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics>([&](auto&& f) { return f.Current(); });
}

inline void CustomXamlResourceLoader::Current(Windows::UI::Xaml::Resources::CustomXamlResourceLoader const& value)
{
    impl::call_factory<CustomXamlResourceLoader, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics>([&](auto&& f) { return f.Current(value); });
}

template <typename D> Windows::Foundation::IInspectable ICustomXamlResourceLoaderOverridesT<D>::GetResource(param::hstring const& resourceId, param::hstring const& objectType, param::hstring const& propertyName, param::hstring const& propertyType) const
{
    return shim().template try_as<ICustomXamlResourceLoaderOverrides>().GetResource(resourceId, objectType, propertyName, propertyType);
}

template <typename D, typename... Interfaces>
struct CustomXamlResourceLoaderT :
    implements<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Resources::ICustomXamlResourceLoader>,
    impl::base<D, Windows::UI::Xaml::Resources::CustomXamlResourceLoader>,
    Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverridesT<D>
{
    using composable = CustomXamlResourceLoader;

protected:
    CustomXamlResourceLoaderT()
    {
        impl::call_factory<Windows::UI::Xaml::Resources::CustomXamlResourceLoader, Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoader> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoader> {};
template<> struct hash<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Resources::ICustomXamlResourceLoaderStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Resources::CustomXamlResourceLoader> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Resources::CustomXamlResourceLoader> {};

}
