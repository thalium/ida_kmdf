// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

enum class DeviceWatcherStatus;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration::Pnp {

enum class PnpObjectType : int32_t
{
    Unknown = 0,
    DeviceInterface = 1,
    DeviceContainer = 2,
    Device = 3,
    DeviceInterfaceClass = 4,
    AssociationEndpoint = 5,
    AssociationEndpointContainer = 6,
    AssociationEndpointService = 7,
    DevicePanel = 8,
};

struct IPnpObject;
struct IPnpObjectStatics;
struct IPnpObjectUpdate;
struct IPnpObjectWatcher;
struct PnpObject;
struct PnpObjectCollection;
struct PnpObjectUpdate;
struct PnpObjectWatcher;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::Enumeration::Pnp::IPnpObject>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::PnpObject>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::PnpObjectUpdate>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::Pnp::PnpObjectType>{ using type = enum_category; };
template <> struct name<Windows::Devices::Enumeration::Pnp::IPnpObject>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.IPnpObject" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.IPnpObjectStatics" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.IPnpObjectUpdate" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.IPnpObjectWatcher" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::PnpObject>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.PnpObject" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.PnpObjectCollection" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::PnpObjectUpdate>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.PnpObjectUpdate" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.PnpObjectWatcher" }; };
template <> struct name<Windows::Devices::Enumeration::Pnp::PnpObjectType>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Pnp.PnpObjectType" }; };
template <> struct guid_storage<Windows::Devices::Enumeration::Pnp::IPnpObject>{ static constexpr guid value{ 0x95C66258,0x733B,0x4A8F,{ 0x93,0xA3,0xDB,0x07,0x8A,0xC8,0x70,0xC1 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>{ static constexpr guid value{ 0xB3C32A3D,0xD168,0x4660,{ 0xBB,0xF3,0xA7,0x33,0xB1,0x4B,0x6E,0x01 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate>{ static constexpr guid value{ 0x6F59E812,0x001E,0x4844,{ 0xBC,0xC6,0x43,0x28,0x86,0x85,0x6A,0x17 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>{ static constexpr guid value{ 0x83C95CA8,0x4772,0x4A7A,{ 0xAC,0xA8,0xE4,0x8C,0x42,0xA8,0x9C,0x44 } }; };
template <> struct default_interface<Windows::Devices::Enumeration::Pnp::PnpObject>{ using type = Windows::Devices::Enumeration::Pnp::IPnpObject; };
template <> struct default_interface<Windows::Devices::Enumeration::Pnp::PnpObjectCollection>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::Pnp::PnpObject>; };
template <> struct default_interface<Windows::Devices::Enumeration::Pnp::PnpObjectUpdate>{ using type = Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate; };
template <> struct default_interface<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher>{ using type = Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher; };

template <> struct abi<Windows::Devices::Enumeration::Pnp::IPnpObject>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::Devices::Enumeration::Pnp::PnpObjectType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Update(void* updateInfo) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::Pnp::IPnpObjectStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromIdAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* id, void* requestedProperties, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsyncAqsFilter(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void* aqsFilter, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void** watcher) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcherAqsFilter(Windows::Devices::Enumeration::Pnp::PnpObjectType type, void* requestedProperties, void* aqsFilter, void** watcher) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::Devices::Enumeration::Pnp::PnpObjectType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceWatcherStatus* status) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Enumeration_Pnp_IPnpObject
{
    Windows::Devices::Enumeration::Pnp::PnpObjectType Type() const;
    hstring Id() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Properties() const;
    void Update(Windows::Devices::Enumeration::Pnp::PnpObjectUpdate const& updateInfo) const;
};
template <> struct consume<Windows::Devices::Enumeration::Pnp::IPnpObject> { template <typename D> using type = consume_Windows_Devices_Enumeration_Pnp_IPnpObject<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObject> CreateFromIdAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::hstring const& id, param::async_iterable<hstring> const& requestedProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::Pnp::PnpObjectCollection> FindAllAsync(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::async_iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter) const;
    Windows::Devices::Enumeration::Pnp::PnpObjectWatcher CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties) const;
    Windows::Devices::Enumeration::Pnp::PnpObjectWatcher CreateWatcher(Windows::Devices::Enumeration::Pnp::PnpObjectType const& type, param::iterable<hstring> const& requestedProperties, param::hstring const& aqsFilter) const;
};
template <> struct consume<Windows::Devices::Enumeration::Pnp::IPnpObjectStatics> { template <typename D> using type = consume_Windows_Devices_Enumeration_Pnp_IPnpObjectStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate
{
    Windows::Devices::Enumeration::Pnp::PnpObjectType Type() const;
    hstring Id() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Enumeration::Pnp::IPnpObjectUpdate> { template <typename D> using type = consume_Windows_Devices_Enumeration_Pnp_IPnpObjectUpdate<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher
{
    winrt::event_token Added(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObject> const& handler) const;
    using Added_revoker = impl::event_revoker<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher, &impl::abi_t<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>::remove_Added>;
    Added_revoker Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObject> const& handler) const;
    void Added(winrt::event_token const& token) const noexcept;
    winrt::event_token Updated(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const;
    using Updated_revoker = impl::event_revoker<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher, &impl::abi_t<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>::remove_Updated>;
    Updated_revoker Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const;
    void Updated(winrt::event_token const& token) const noexcept;
    winrt::event_token Removed(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const;
    using Removed_revoker = impl::event_revoker<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher, &impl::abi_t<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>::remove_Removed>;
    Removed_revoker Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Devices::Enumeration::Pnp::PnpObjectUpdate> const& handler) const;
    void Removed(winrt::event_token const& token) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher, &impl::abi_t<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token Stopped(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using Stopped_revoker = impl::event_revoker<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher, &impl::abi_t<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher>::remove_Stopped>;
    Stopped_revoker Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::Pnp::PnpObjectWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void Stopped(winrt::event_token const& token) const noexcept;
    Windows::Devices::Enumeration::DeviceWatcherStatus Status() const;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Devices::Enumeration::Pnp::IPnpObjectWatcher> { template <typename D> using type = consume_Windows_Devices_Enumeration_Pnp_IPnpObjectWatcher<D>; };

}
