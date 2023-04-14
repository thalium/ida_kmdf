// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.Pnp.2.h"
#include "winrt/Windows.Devices.Enumeration.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Enumeration::Pnp::PnpObjectType consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Type() const
{
    Windows::Devices::Enumeration::Pnp::PnpObjectType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObject)->get_Type(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObject)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObject)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>::Update(Windows::Devices::Enumeration::Pnp::PnpObjectUpdate const& updateInfo) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObject)->Update(get_abi(updateInfo)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObject> consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::CreateFromIdAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::hstring const& id, param::async_iterable<hstring> const& requestedProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObject> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->CreateFromIdAsync(get_abi(type), get_abi(id), get_abi(requestedProperties), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->FindAllAsync(get_abi(type), get_abi(requestedProperties), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->FindAllAsyncAqsFilter(get_abi(type), get_abi(requestedProperties), get_abi(aqsFilter), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Devices::Enumeration::Pnp::PnpObjectWatcher consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties) const
{
    Windows::Devices::Enumeration::Pnp::PnpObjectWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->CreateWatcher(get_abi(type), get_abi(requestedProperties), put_abi(watcher)));
    return watcher;
}

template <typename D> Windows::Devices::Enumeration::Pnp::PnpObjectWatcher consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>::CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter) const
{
    Windows::Devices::Enumeration::Pnp::PnpObjectWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectStatics)->CreateWatcherAqsFilter(get_abi(type), get_abi(requestedProperties), get_abi(aqsFilter), put_abi(watcher)));
    return watcher;
}

template <typename D> Windows::Devices::Enumeration::Pnp::PnpObjectType consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>::Type() const
{
    Windows::Devices::Enumeration::Pnp::PnpObjectType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate)->get_Type(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObject> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObject> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped_revoker consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcherStatus consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Status() const
{
    Windows::Devices::Enumeration::DeviceWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->Start());
}

template <typename D> void consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher)->Stop());
}

template <typename D>
struct produce<D, Windows::Devices::Enumeration::Pnp::IPnpObject> : produce_base<D, Windows::Devices::Enumeration::Pnp::IPnpObject>
{
    int32_t WINRT_CALL get_Type(Windows::Devices::Enumeration::Pnp::PnpObjectType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Devices::Enumeration::Pnp::PnpObjectType));
            *value = detach_from<Windows::Devices::Enumeration::Pnp::PnpObjectType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
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

    int32_t WINRT_CALL Update(void* updateInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void), Windows::Devices::Enumeration::Pnp::PnpObjectUpdate const&);
            this->shim().Update(*reinterpret_cast<Windows::Devices::Enumeration::Pnp::PnpObjectUpdate const*>(&updateInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics> : produce_base<D, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>
{
    int32_t WINRT_CALL CreateFromIdAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* id, void* requestedProperties, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObject>), Windows::Devices::Enumeration::Pnp::PnpObjectType const, hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObject>>(this->shim().CreateFromIdAsync(*reinterpret_cast<Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>), Windows::Devices::Enumeration::Pnp::PnpObjectType const, Windows::Foundation::Collections::IIterable<hstring> const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>>(this->shim().FindAllAsync(*reinterpret_cast<Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncAqsFilter(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void* aqsFilter, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>), Windows::Devices::Enumeration::Pnp::PnpObjectType const, Windows::Foundation::Collections::IIterable<hstring> const, hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>>(this->shim().FindAllAsync(*reinterpret_cast<Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties), *reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::Pnp::PnpObjectWatcher), Windows::Devices::Enumeration::Pnp::PnpObjectType const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *watcher = detach_from<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>(this->shim().CreateWatcher(*reinterpret_cast<Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherAqsFilter(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void* aqsFilter, void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::Pnp::PnpObjectWatcher), Windows::Devices::Enumeration::Pnp::PnpObjectType const&, Windows::Foundation::Collections::IIterable<hstring> const&, hstring const&);
            *watcher = detach_from<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>(this->shim().CreateWatcher(*reinterpret_cast<Windows::Devices::Enumeration::Pnp::PnpObjectType const*>(&type), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedProperties), *reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate> : produce_base<D, Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate>
{
    int32_t WINRT_CALL get_Type(Windows::Devices::Enumeration::Pnp::PnpObjectType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Devices::Enumeration::Pnp::PnpObjectType));
            *value = detach_from<Windows::Devices::Enumeration::Pnp::PnpObjectType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
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
struct produce<D, Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher> : produce_base<D, Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObject> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObject> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcherStatus));
            *status = detach_from<Windows::Devices::Enumeration::DeviceWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration::Pnp {

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObject> PnpObject::CreateFromIdAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::hstring const& id, param::async_iterable<hstring> const& requestedProperties)
{
    return impl::call_factory<PnpObject, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>([&](auto&& f) { return f.CreateFromIdAsync(type, id, requestedProperties); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> PnpObject::FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties)
{
    return impl::call_factory<PnpObject, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>([&](auto&& f) { return f.FindAllAsync(type, requestedProperties); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> PnpObject::FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter)
{
    return impl::call_factory<PnpObject, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>([&](auto&& f) { return f.FindAllAsync(type, requestedProperties, aqsFilter); });
}

inline Windows::Devices::Enumeration::Pnp::PnpObjectWatcher PnpObject::CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties)
{
    return impl::call_factory<PnpObject, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>([&](auto&& f) { return f.CreateWatcher(type, requestedProperties); });
}

inline Windows::Devices::Enumeration::Pnp::PnpObjectWatcher PnpObject::CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter)
{
    return impl::call_factory<PnpObject, Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>([&](auto&& f) { return f.CreateWatcher(type, requestedProperties, aqsFilter); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObject> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::IPnpObject> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectStatics> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObject> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::PnpObject> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectCollection> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::Pnp::PnpObjectWatcher> {};

}
