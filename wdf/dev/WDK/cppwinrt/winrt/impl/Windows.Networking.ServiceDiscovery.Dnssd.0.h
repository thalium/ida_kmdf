// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Networking {

struct HostName;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Connectivity {

struct NetworkAdapter;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

struct DatagramSocket;
struct StreamSocketListener;

}

WINRT_EXPORT namespace winrt::Windows::Networking::ServiceDiscovery::Dnssd {

enum class DnssdRegistrationStatus : int32_t
{
    Success = 0,
    InvalidServiceName = 1,
    ServerError = 2,
    SecurityError = 3,
};

enum class DnssdServiceWatcherStatus : int32_t
{
    Created = 0,
    Started = 1,
    EnumerationCompleted = 2,
    Stopping = 3,
    Stopped = 4,
    Aborted = 5,
};

struct IDnssdRegistrationResult;
struct IDnssdServiceInstance;
struct IDnssdServiceInstanceFactory;
struct IDnssdServiceWatcher;
struct DnssdRegistrationResult;
struct DnssdServiceInstance;
struct DnssdServiceInstanceCollection;
struct DnssdServiceWatcher;

}

namespace winrt::impl {

template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance>{ using type = interface_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>{ using type = interface_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>{ using type = interface_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ using type = class_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>{ using type = class_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstanceCollection>{ using type = class_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher>{ using type = class_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus>{ using type = enum_category; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.IDnssdRegistrationResult" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.IDnssdServiceInstance" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.IDnssdServiceInstanceFactory" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.IDnssdServiceWatcher" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.DnssdRegistrationResult" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.DnssdServiceInstance" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstanceCollection>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.DnssdServiceInstanceCollection" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.DnssdServiceWatcher" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.DnssdRegistrationStatus" }; };
template <> struct name<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus>{ static constexpr auto & value{ L"Windows.Networking.ServiceDiscovery.Dnssd.DnssdServiceWatcherStatus" }; };
template <> struct guid_storage<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult>{ static constexpr guid value{ 0x3D786AD2,0xE606,0x5350,{ 0x73,0xEA,0x7E,0x97,0xF0,0x66,0x16,0x2F } }; };
template <> struct guid_storage<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance>{ static constexpr guid value{ 0xE246DB7E,0x98A5,0x4CA1,{ 0xB9,0xE4,0xC2,0x53,0xD3,0x3C,0x35,0xFF } }; };
template <> struct guid_storage<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>{ static constexpr guid value{ 0x6CB061A1,0xC478,0x4331,{ 0x96,0x84,0x4A,0xF2,0x18,0x6C,0x0A,0x2B } }; };
template <> struct guid_storage<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>{ static constexpr guid value{ 0xCC34D9C1,0xDB7D,0x4B69,{ 0x98,0x3D,0xC6,0xF8,0x3F,0x20,0x56,0x82 } }; };
template <> struct default_interface<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ using type = Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult; };
template <> struct default_interface<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>{ using type = Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance; };
template <> struct default_interface<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstanceCollection>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>; };
template <> struct default_interface<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher>{ using type = Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher; };

template <> struct abi<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IPAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasInstanceNameChanged(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DnssdServiceInstanceName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DnssdServiceInstanceName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HostName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HostName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Port(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Port(uint16_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Priority(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Priority(uint16_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Weight(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Weight(uint16_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TextAttributes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterStreamSocketListenerAsync1(void* socket, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterStreamSocketListenerAsync2(void* socket, void* adapter, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterDatagramSocketAsync1(void* socket, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterDatagramSocketAsync2(void* socket, void* adapter, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* dnssdServiceInstanceName, void* hostName, uint16_t port, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus* status) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <typename D>
struct consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult
{
    Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus Status() const;
    Windows::Networking::HostName IPAddress() const;
    bool HasInstanceNameChanged() const;
};
template <> struct consume<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult> { template <typename D> using type = consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>; };

template <typename D>
struct consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance
{
    hstring DnssdServiceInstanceName() const;
    void DnssdServiceInstanceName(param::hstring const& value) const;
    Windows::Networking::HostName HostName() const;
    void HostName(Windows::Networking::HostName const& value) const;
    uint16_t Port() const;
    void Port(uint16_t value) const;
    uint16_t Priority() const;
    void Priority(uint16_t value) const;
    uint16_t Weight() const;
    void Weight(uint16_t value) const;
    Windows::Foundation::Collections::IMap<hstring, hstring> TextAttributes() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> RegisterStreamSocketListenerAsync(Windows::Networking::Sockets::StreamSocketListener const& socket) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> RegisterStreamSocketListenerAsync(Windows::Networking::Sockets::StreamSocketListener const& socket, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> RegisterDatagramSocketAsync(Windows::Networking::Sockets::DatagramSocket const& socket) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> RegisterDatagramSocketAsync(Windows::Networking::Sockets::DatagramSocket const& socket, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const;
};
template <> struct consume<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance> { template <typename D> using type = consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>; };

template <typename D>
struct consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstanceFactory
{
    Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance Create(param::hstring const& dnssdServiceInstanceName, Windows::Networking::HostName const& hostName, uint16_t port) const;
};
template <> struct consume<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory> { template <typename D> using type = consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstanceFactory<D>; };

template <typename D>
struct consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher
{
    winrt::event_token Added(Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const& handler) const;
    using Added_revoker = impl::event_revoker<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher, &impl::abi_t<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>::remove_Added>;
    Added_revoker Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const& handler) const;
    void Added(winrt::event_token const& token) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher, &impl::abi_t<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using Stopped_revoker = impl::event_revoker<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher, &impl::abi_t<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>::remove_Stopped>;
    Stopped_revoker Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void Stopped(winrt::event_token const& token) const noexcept;
    Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus Status() const;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher> { template <typename D> using type = consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>; };

}
