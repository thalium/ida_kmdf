// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Resources_IResourceLoader<D>::GetString(param::hstring const& resource) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoader)->GetString(get_abi(resource), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Resources_IResourceLoader2<D>::GetStringForUri(Windows::Foundation::Uri const& uri) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoader2)->GetStringForUri(get_abi(uri), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::ResourceLoader consume_Windows_ApplicationModel_Resources_IResourceLoaderFactory<D>::CreateResourceLoaderByName(param::hstring const& name) const
{
    Windows::ApplicationModel::Resources::ResourceLoader loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderFactory)->CreateResourceLoaderByName(get_abi(name), put_abi(loader)));
    return loader;
}

template <typename D> hstring consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics<D>::GetStringForReference(Windows::Foundation::Uri const& uri) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderStatics)->GetStringForReference(get_abi(uri), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Resources::ResourceLoader consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::Resources::ResourceLoader loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForCurrentView(put_abi(loader)));
    return loader;
}

template <typename D> Windows::ApplicationModel::Resources::ResourceLoader consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForCurrentView(param::hstring const& name) const
{
    Windows::ApplicationModel::Resources::ResourceLoader loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForCurrentViewWithName(get_abi(name), put_abi(loader)));
    return loader;
}

template <typename D> Windows::ApplicationModel::Resources::ResourceLoader consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForViewIndependentUse() const
{
    Windows::ApplicationModel::Resources::ResourceLoader loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForViewIndependentUse(put_abi(loader)));
    return loader;
}

template <typename D> Windows::ApplicationModel::Resources::ResourceLoader consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics2<D>::GetForViewIndependentUse(param::hstring const& name) const
{
    Windows::ApplicationModel::Resources::ResourceLoader loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderStatics2)->GetForViewIndependentUseWithName(get_abi(name), put_abi(loader)));
    return loader;
}

template <typename D> Windows::ApplicationModel::Resources::ResourceLoader consume_Windows_ApplicationModel_Resources_IResourceLoaderStatics3<D>::GetForUIContext(Windows::UI::UIContext const& context) const
{
    Windows::ApplicationModel::Resources::ResourceLoader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Resources::IResourceLoaderStatics3)->GetForUIContext(get_abi(context), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::IResourceLoader> : produce_base<D, Windows::ApplicationModel::Resources::IResourceLoader>
{
    int32_t WINRT_CALL GetString(void* resource, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetString, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().GetString(*reinterpret_cast<hstring const*>(&resource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::IResourceLoader2> : produce_base<D, Windows::ApplicationModel::Resources::IResourceLoader2>
{
    int32_t WINRT_CALL GetStringForUri(void* uri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringForUri, WINRT_WRAP(hstring), Windows::Foundation::Uri const&);
            *value = detach_from<hstring>(this->shim().GetStringForUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::IResourceLoaderFactory> : produce_base<D, Windows::ApplicationModel::Resources::IResourceLoaderFactory>
{
    int32_t WINRT_CALL CreateResourceLoaderByName(void* name, void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateResourceLoaderByName, WINRT_WRAP(Windows::ApplicationModel::Resources::ResourceLoader), hstring const&);
            *loader = detach_from<Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().CreateResourceLoaderByName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::IResourceLoaderStatics> : produce_base<D, Windows::ApplicationModel::Resources::IResourceLoaderStatics>
{
    int32_t WINRT_CALL GetStringForReference(void* uri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringForReference, WINRT_WRAP(hstring), Windows::Foundation::Uri const&);
            *value = detach_from<hstring>(this->shim().GetStringForReference(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::IResourceLoaderStatics2> : produce_base<D, Windows::ApplicationModel::Resources::IResourceLoaderStatics2>
{
    int32_t WINRT_CALL GetForCurrentView(void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::Resources::ResourceLoader));
            *loader = detach_from<Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForCurrentViewWithName(void* name, void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::Resources::ResourceLoader), hstring const&);
            *loader = detach_from<Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForCurrentView(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForViewIndependentUse(void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForViewIndependentUse, WINRT_WRAP(Windows::ApplicationModel::Resources::ResourceLoader));
            *loader = detach_from<Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForViewIndependentUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForViewIndependentUseWithName(void* name, void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForViewIndependentUse, WINRT_WRAP(Windows::ApplicationModel::Resources::ResourceLoader), hstring const&);
            *loader = detach_from<Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForViewIndependentUse(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Resources::IResourceLoaderStatics3> : produce_base<D, Windows::ApplicationModel::Resources::IResourceLoaderStatics3>
{
    int32_t WINRT_CALL GetForUIContext(void* context, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUIContext, WINRT_WRAP(Windows::ApplicationModel::Resources::ResourceLoader), Windows::UI::UIContext const&);
            *result = detach_from<Windows::ApplicationModel::Resources::ResourceLoader>(this->shim().GetForUIContext(*reinterpret_cast<Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources {

inline ResourceLoader::ResourceLoader() :
    ResourceLoader(impl::call_factory<ResourceLoader>([](auto&& f) { return f.template ActivateInstance<ResourceLoader>(); }))
{}

inline ResourceLoader::ResourceLoader(param::hstring const& name) :
    ResourceLoader(impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderFactory>([&](auto&& f) { return f.CreateResourceLoaderByName(name); }))
{}

inline hstring ResourceLoader::GetStringForReference(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderStatics>([&](auto&& f) { return f.GetStringForReference(uri); });
}

inline Windows::ApplicationModel::Resources::ResourceLoader ResourceLoader::GetForCurrentView()
{
    return impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderStatics2>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::ApplicationModel::Resources::ResourceLoader ResourceLoader::GetForCurrentView(param::hstring const& name)
{
    return impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderStatics2>([&](auto&& f) { return f.GetForCurrentView(name); });
}

inline Windows::ApplicationModel::Resources::ResourceLoader ResourceLoader::GetForViewIndependentUse()
{
    return impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderStatics2>([&](auto&& f) { return f.GetForViewIndependentUse(); });
}

inline Windows::ApplicationModel::Resources::ResourceLoader ResourceLoader::GetForViewIndependentUse(param::hstring const& name)
{
    return impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderStatics2>([&](auto&& f) { return f.GetForViewIndependentUse(name); });
}

inline Windows::ApplicationModel::Resources::ResourceLoader ResourceLoader::GetForUIContext(Windows::UI::UIContext const& context)
{
    return impl::call_factory<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoaderStatics3>([&](auto&& f) { return f.GetForUIContext(context); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::IResourceLoader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoader2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::IResourceLoader2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::IResourceLoaderFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::IResourceLoaderStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Resources::ResourceLoader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Resources::ResourceLoader> {};

}
