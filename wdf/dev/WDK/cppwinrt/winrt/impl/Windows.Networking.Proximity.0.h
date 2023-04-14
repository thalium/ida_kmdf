// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Networking {

struct HostName;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

struct StreamSocket;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Proximity {

enum class PeerDiscoveryTypes : uint32_t
{
    None = 0x0,
    Browse = 0x1,
    Triggered = 0x2,
};

enum class PeerRole : int32_t
{
    Peer = 0,
    Host = 1,
    Client = 2,
};

enum class PeerWatcherStatus : int32_t
{
    Created = 0,
    Started = 1,
    EnumerationCompleted = 2,
    Stopping = 3,
    Stopped = 4,
    Aborted = 5,
};

enum class TriggeredConnectState : int32_t
{
    PeerFound = 0,
    Listening = 1,
    Connecting = 2,
    Completed = 3,
    Canceled = 4,
    Failed = 5,
};

struct IConnectionRequestedEventArgs;
struct IPeerFinderStatics;
struct IPeerFinderStatics2;
struct IPeerInformation;
struct IPeerInformation3;
struct IPeerInformationWithHostAndService;
struct IPeerWatcher;
struct IProximityDevice;
struct IProximityDeviceStatics;
struct IProximityMessage;
struct ITriggeredConnectionStateChangedEventArgs;
struct ConnectionRequestedEventArgs;
struct PeerFinder;
struct PeerInformation;
struct PeerWatcher;
struct ProximityDevice;
struct ProximityMessage;
struct TriggeredConnectionStateChangedEventArgs;
struct DeviceArrivedEventHandler;
struct DeviceDepartedEventHandler;
struct MessageReceivedHandler;
struct MessageTransmittedHandler;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Networking::Proximity::PeerDiscoveryTypes> : std::true_type {};
template <> struct category<Windows::Networking::Proximity::IConnectionRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IPeerFinderStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IPeerFinderStatics2>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IPeerInformation>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IPeerInformation3>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IPeerInformationWithHostAndService>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IPeerWatcher>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IProximityDevice>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IProximityDeviceStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::IProximityMessage>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::Proximity::ConnectionRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::PeerFinder>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::PeerInformation>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::PeerWatcher>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::ProximityDevice>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::ProximityMessage>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::Proximity::PeerDiscoveryTypes>{ using type = enum_category; };
template <> struct category<Windows::Networking::Proximity::PeerRole>{ using type = enum_category; };
template <> struct category<Windows::Networking::Proximity::PeerWatcherStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::Proximity::TriggeredConnectState>{ using type = enum_category; };
template <> struct category<Windows::Networking::Proximity::DeviceArrivedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::Networking::Proximity::DeviceDepartedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::Networking::Proximity::MessageReceivedHandler>{ using type = delegate_category; };
template <> struct category<Windows::Networking::Proximity::MessageTransmittedHandler>{ using type = delegate_category; };
template <> struct name<Windows::Networking::Proximity::IConnectionRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IConnectionRequestedEventArgs" }; };
template <> struct name<Windows::Networking::Proximity::IPeerFinderStatics>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IPeerFinderStatics" }; };
template <> struct name<Windows::Networking::Proximity::IPeerFinderStatics2>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IPeerFinderStatics2" }; };
template <> struct name<Windows::Networking::Proximity::IPeerInformation>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IPeerInformation" }; };
template <> struct name<Windows::Networking::Proximity::IPeerInformation3>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IPeerInformation3" }; };
template <> struct name<Windows::Networking::Proximity::IPeerInformationWithHostAndService>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IPeerInformationWithHostAndService" }; };
template <> struct name<Windows::Networking::Proximity::IPeerWatcher>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IPeerWatcher" }; };
template <> struct name<Windows::Networking::Proximity::IProximityDevice>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IProximityDevice" }; };
template <> struct name<Windows::Networking::Proximity::IProximityDeviceStatics>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IProximityDeviceStatics" }; };
template <> struct name<Windows::Networking::Proximity::IProximityMessage>{ static constexpr auto & value{ L"Windows.Networking.Proximity.IProximityMessage" }; };
template <> struct name<Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.Proximity.ITriggeredConnectionStateChangedEventArgs" }; };
template <> struct name<Windows::Networking::Proximity::ConnectionRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.Proximity.ConnectionRequestedEventArgs" }; };
template <> struct name<Windows::Networking::Proximity::PeerFinder>{ static constexpr auto & value{ L"Windows.Networking.Proximity.PeerFinder" }; };
template <> struct name<Windows::Networking::Proximity::PeerInformation>{ static constexpr auto & value{ L"Windows.Networking.Proximity.PeerInformation" }; };
template <> struct name<Windows::Networking::Proximity::PeerWatcher>{ static constexpr auto & value{ L"Windows.Networking.Proximity.PeerWatcher" }; };
template <> struct name<Windows::Networking::Proximity::ProximityDevice>{ static constexpr auto & value{ L"Windows.Networking.Proximity.ProximityDevice" }; };
template <> struct name<Windows::Networking::Proximity::ProximityMessage>{ static constexpr auto & value{ L"Windows.Networking.Proximity.ProximityMessage" }; };
template <> struct name<Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.Proximity.TriggeredConnectionStateChangedEventArgs" }; };
template <> struct name<Windows::Networking::Proximity::PeerDiscoveryTypes>{ static constexpr auto & value{ L"Windows.Networking.Proximity.PeerDiscoveryTypes" }; };
template <> struct name<Windows::Networking::Proximity::PeerRole>{ static constexpr auto & value{ L"Windows.Networking.Proximity.PeerRole" }; };
template <> struct name<Windows::Networking::Proximity::PeerWatcherStatus>{ static constexpr auto & value{ L"Windows.Networking.Proximity.PeerWatcherStatus" }; };
template <> struct name<Windows::Networking::Proximity::TriggeredConnectState>{ static constexpr auto & value{ L"Windows.Networking.Proximity.TriggeredConnectState" }; };
template <> struct name<Windows::Networking::Proximity::DeviceArrivedEventHandler>{ static constexpr auto & value{ L"Windows.Networking.Proximity.DeviceArrivedEventHandler" }; };
template <> struct name<Windows::Networking::Proximity::DeviceDepartedEventHandler>{ static constexpr auto & value{ L"Windows.Networking.Proximity.DeviceDepartedEventHandler" }; };
template <> struct name<Windows::Networking::Proximity::MessageReceivedHandler>{ static constexpr auto & value{ L"Windows.Networking.Proximity.MessageReceivedHandler" }; };
template <> struct name<Windows::Networking::Proximity::MessageTransmittedHandler>{ static constexpr auto & value{ L"Windows.Networking.Proximity.MessageTransmittedHandler" }; };
template <> struct guid_storage<Windows::Networking::Proximity::IConnectionRequestedEventArgs>{ static constexpr guid value{ 0xEB6891AE,0x4F1E,0x4C66,{ 0xBD,0x0D,0x46,0x92,0x4A,0x94,0x2E,0x08 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IPeerFinderStatics>{ static constexpr guid value{ 0x914B3B61,0xF6E1,0x47C4,{ 0xA1,0x4C,0x14,0x8A,0x19,0x03,0xD0,0xC6 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IPeerFinderStatics2>{ static constexpr guid value{ 0xD6E73C65,0xFDD0,0x4B0B,{ 0x93,0x12,0x86,0x64,0x08,0x93,0x5D,0x82 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IPeerInformation>{ static constexpr guid value{ 0x20024F08,0x9FFF,0x45F4,{ 0xB6,0xE9,0x40,0x8B,0x2E,0xBE,0xF3,0x73 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IPeerInformation3>{ static constexpr guid value{ 0xB20F612A,0xDBD0,0x40F8,{ 0x95,0xBD,0x2D,0x42,0x09,0xC7,0x83,0x6F } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IPeerInformationWithHostAndService>{ static constexpr guid value{ 0xECC7CCAD,0x1B70,0x4E8B,{ 0x92,0xDB,0xBB,0xE7,0x81,0x41,0x93,0x08 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IPeerWatcher>{ static constexpr guid value{ 0x3CEE21F8,0x2FA6,0x4679,{ 0x96,0x91,0x03,0xC9,0x4A,0x42,0x0F,0x34 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IProximityDevice>{ static constexpr guid value{ 0xEFA8A552,0xF6E1,0x4329,{ 0xA0,0xFC,0xAB,0x6B,0x0F,0xD2,0x82,0x62 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IProximityDeviceStatics>{ static constexpr guid value{ 0x914BA01D,0xF6E1,0x47C4,{ 0xA1,0x4C,0x14,0x8A,0x19,0x03,0xD0,0xC6 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::IProximityMessage>{ static constexpr guid value{ 0xEFAB0782,0xF6E1,0x4675,{ 0xA0,0x45,0xD8,0xE3,0x20,0xC2,0x48,0x08 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>{ static constexpr guid value{ 0xC6A780AD,0xF6E1,0x4D54,{ 0x96,0xE2,0x33,0xF6,0x20,0xBC,0xA8,0x8A } }; };
template <> struct guid_storage<Windows::Networking::Proximity::DeviceArrivedEventHandler>{ static constexpr guid value{ 0xEFA9DA69,0xF6E1,0x49C9,{ 0xA4,0x9E,0x8E,0x0F,0xC5,0x8F,0xB9,0x11 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::DeviceDepartedEventHandler>{ static constexpr guid value{ 0xEFA9DA69,0xF6E2,0x49C9,{ 0xA4,0x9E,0x8E,0x0F,0xC5,0x8F,0xB9,0x11 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::MessageReceivedHandler>{ static constexpr guid value{ 0xEFAB0782,0xF6E2,0x4675,{ 0xA0,0x45,0xD8,0xE3,0x20,0xC2,0x48,0x08 } }; };
template <> struct guid_storage<Windows::Networking::Proximity::MessageTransmittedHandler>{ static constexpr guid value{ 0xEFAA0B4A,0xF6E2,0x4D7D,{ 0x85,0x6C,0x78,0xFC,0x8E,0xFC,0x02,0x1E } }; };
template <> struct default_interface<Windows::Networking::Proximity::ConnectionRequestedEventArgs>{ using type = Windows::Networking::Proximity::IConnectionRequestedEventArgs; };
template <> struct default_interface<Windows::Networking::Proximity::PeerInformation>{ using type = Windows::Networking::Proximity::IPeerInformation; };
template <> struct default_interface<Windows::Networking::Proximity::PeerWatcher>{ using type = Windows::Networking::Proximity::IPeerWatcher; };
template <> struct default_interface<Windows::Networking::Proximity::ProximityDevice>{ using type = Windows::Networking::Proximity::IProximityDevice; };
template <> struct default_interface<Windows::Networking::Proximity::ProximityMessage>{ using type = Windows::Networking::Proximity::IProximityMessage; };
template <> struct default_interface<Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs>{ using type = Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs; };

template <> struct abi<Windows::Networking::Proximity::IConnectionRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PeerInformation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IPeerFinderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllowBluetooth(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowBluetooth(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AllowInfrastructure(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowInfrastructure(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AllowWiFiDirect(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowWiFiDirect(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedDiscoveryTypes(Windows::Networking::Proximity::PeerDiscoveryTypes* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlternateIdentities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL StartWithMessage(void* peerMessage) noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
    virtual int32_t WINRT_CALL add_TriggeredConnectionStateChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TriggeredConnectionStateChanged(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_ConnectionRequested(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ConnectionRequested(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllPeersAsync(void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL ConnectAsync(void* peerInformation, void** asyncOp) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IPeerFinderStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Role(Windows::Networking::Proximity::PeerRole* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Role(Windows::Networking::Proximity::PeerRole value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DiscoveryData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DiscoveryData(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcher(void** watcher) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IPeerInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IPeerInformation3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DiscoveryData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IPeerInformationWithHostAndService>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HostName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IPeerWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::Proximity::PeerWatcherStatus* status) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IProximityDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SubscribeForMessage(void* messageType, void* messageReceivedHandler, int64_t* subscriptionId) noexcept = 0;
    virtual int32_t WINRT_CALL PublishMessage(void* messageType, void* message, int64_t* messageId) noexcept = 0;
    virtual int32_t WINRT_CALL PublishMessageWithCallback(void* messageType, void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept = 0;
    virtual int32_t WINRT_CALL PublishBinaryMessage(void* messageType, void* message, int64_t* messageId) noexcept = 0;
    virtual int32_t WINRT_CALL PublishBinaryMessageWithCallback(void* messageType, void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept = 0;
    virtual int32_t WINRT_CALL PublishUriMessage(void* message, int64_t* messageId) noexcept = 0;
    virtual int32_t WINRT_CALL PublishUriMessageWithCallback(void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept = 0;
    virtual int32_t WINRT_CALL StopSubscribingForMessage(int64_t subscriptionId) noexcept = 0;
    virtual int32_t WINRT_CALL StopPublishingMessage(int64_t messageId) noexcept = 0;
    virtual int32_t WINRT_CALL add_DeviceArrived(void* arrivedHandler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DeviceArrived(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_DeviceDeparted(void* departedHandler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DeviceDeparted(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxMessageBytes(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitsPerSecond(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IProximityDeviceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void** selector) noexcept = 0;
    virtual int32_t WINRT_CALL GetDefault(void** proximityDevice) noexcept = 0;
    virtual int32_t WINRT_CALL FromId(void* deviceId, void** proximityDevice) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::IProximityMessage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MessageType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubscriptionId(int64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataAsString(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::Networking::Proximity::TriggeredConnectState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Socket(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::DeviceArrivedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::DeviceDepartedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::MessageReceivedHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* message) noexcept = 0;
};};

template <> struct abi<Windows::Networking::Proximity::MessageTransmittedHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, int64_t messageId) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Networking_Proximity_IConnectionRequestedEventArgs
{
    Windows::Networking::Proximity::PeerInformation PeerInformation() const;
};
template <> struct consume<Windows::Networking::Proximity::IConnectionRequestedEventArgs> { template <typename D> using type = consume_Windows_Networking_Proximity_IConnectionRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IPeerFinderStatics
{
    bool AllowBluetooth() const;
    void AllowBluetooth(bool value) const;
    bool AllowInfrastructure() const;
    void AllowInfrastructure(bool value) const;
    bool AllowWiFiDirect() const;
    void AllowWiFiDirect(bool value) const;
    hstring DisplayName() const;
    void DisplayName(param::hstring const& value) const;
    Windows::Networking::Proximity::PeerDiscoveryTypes SupportedDiscoveryTypes() const;
    Windows::Foundation::Collections::IMap<hstring, hstring> AlternateIdentities() const;
    void Start() const;
    void Start(param::hstring const& peerMessage) const;
    void Stop() const;
    winrt::event_token TriggeredConnectionStateChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const;
    using TriggeredConnectionStateChanged_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerFinderStatics, &impl::abi_t<Windows::Networking::Proximity::IPeerFinderStatics>::remove_TriggeredConnectionStateChanged>;
    TriggeredConnectionStateChanged_revoker TriggeredConnectionStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const;
    void TriggeredConnectionStateChanged(winrt::event_token const& cookie) const noexcept;
    winrt::event_token ConnectionRequested(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const;
    using ConnectionRequested_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerFinderStatics, &impl::abi_t<Windows::Networking::Proximity::IPeerFinderStatics>::remove_ConnectionRequested>;
    ConnectionRequested_revoker ConnectionRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const;
    void ConnectionRequested(winrt::event_token const& cookie) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Proximity::PeerInformation>> FindAllPeersAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::Sockets::StreamSocket> ConnectAsync(Windows::Networking::Proximity::PeerInformation const& peerInformation) const;
};
template <> struct consume<Windows::Networking::Proximity::IPeerFinderStatics> { template <typename D> using type = consume_Windows_Networking_Proximity_IPeerFinderStatics<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IPeerFinderStatics2
{
    Windows::Networking::Proximity::PeerRole Role() const;
    void Role(Windows::Networking::Proximity::PeerRole const& value) const;
    Windows::Storage::Streams::IBuffer DiscoveryData() const;
    void DiscoveryData(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Networking::Proximity::PeerWatcher CreateWatcher() const;
};
template <> struct consume<Windows::Networking::Proximity::IPeerFinderStatics2> { template <typename D> using type = consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IPeerInformation
{
    hstring DisplayName() const;
};
template <> struct consume<Windows::Networking::Proximity::IPeerInformation> { template <typename D> using type = consume_Windows_Networking_Proximity_IPeerInformation<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IPeerInformation3
{
    hstring Id() const;
    Windows::Storage::Streams::IBuffer DiscoveryData() const;
};
template <> struct consume<Windows::Networking::Proximity::IPeerInformation3> { template <typename D> using type = consume_Windows_Networking_Proximity_IPeerInformation3<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService
{
    Windows::Networking::HostName HostName() const;
    hstring ServiceName() const;
};
template <> struct consume<Windows::Networking::Proximity::IPeerInformationWithHostAndService> { template <typename D> using type = consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IPeerWatcher
{
    winrt::event_token Added(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const;
    using Added_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<Windows::Networking::Proximity::IPeerWatcher>::remove_Added>;
    Added_revoker Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const;
    void Added(winrt::event_token const& token) const noexcept;
    winrt::event_token Removed(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const;
    using Removed_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<Windows::Networking::Proximity::IPeerWatcher>::remove_Removed>;
    Removed_revoker Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const;
    void Removed(winrt::event_token const& token) const noexcept;
    winrt::event_token Updated(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const;
    using Updated_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<Windows::Networking::Proximity::IPeerWatcher>::remove_Updated>;
    Updated_revoker Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const;
    void Updated(winrt::event_token const& token) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<Windows::Networking::Proximity::IPeerWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using Stopped_revoker = impl::event_revoker<Windows::Networking::Proximity::IPeerWatcher, &impl::abi_t<Windows::Networking::Proximity::IPeerWatcher>::remove_Stopped>;
    Stopped_revoker Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void Stopped(winrt::event_token const& token) const noexcept;
    Windows::Networking::Proximity::PeerWatcherStatus Status() const;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Networking::Proximity::IPeerWatcher> { template <typename D> using type = consume_Windows_Networking_Proximity_IPeerWatcher<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IProximityDevice
{
    int64_t SubscribeForMessage(param::hstring const& messageType, Windows::Networking::Proximity::MessageReceivedHandler const& messageReceivedHandler) const;
    int64_t PublishMessage(param::hstring const& messageType, param::hstring const& message) const;
    int64_t PublishMessage(param::hstring const& messageType, param::hstring const& message, Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const;
    int64_t PublishBinaryMessage(param::hstring const& messageType, Windows::Storage::Streams::IBuffer const& message) const;
    int64_t PublishBinaryMessage(param::hstring const& messageType, Windows::Storage::Streams::IBuffer const& message, Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const;
    int64_t PublishUriMessage(Windows::Foundation::Uri const& message) const;
    int64_t PublishUriMessage(Windows::Foundation::Uri const& message, Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const;
    void StopSubscribingForMessage(int64_t subscriptionId) const;
    void StopPublishingMessage(int64_t messageId) const;
    winrt::event_token DeviceArrived(Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const;
    using DeviceArrived_revoker = impl::event_revoker<Windows::Networking::Proximity::IProximityDevice, &impl::abi_t<Windows::Networking::Proximity::IProximityDevice>::remove_DeviceArrived>;
    DeviceArrived_revoker DeviceArrived(auto_revoke_t, Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const;
    void DeviceArrived(winrt::event_token const& cookie) const noexcept;
    winrt::event_token DeviceDeparted(Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const;
    using DeviceDeparted_revoker = impl::event_revoker<Windows::Networking::Proximity::IProximityDevice, &impl::abi_t<Windows::Networking::Proximity::IProximityDevice>::remove_DeviceDeparted>;
    DeviceDeparted_revoker DeviceDeparted(auto_revoke_t, Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const;
    void DeviceDeparted(winrt::event_token const& cookie) const noexcept;
    uint32_t MaxMessageBytes() const;
    uint64_t BitsPerSecond() const;
    hstring DeviceId() const;
};
template <> struct consume<Windows::Networking::Proximity::IProximityDevice> { template <typename D> using type = consume_Windows_Networking_Proximity_IProximityDevice<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IProximityDeviceStatics
{
    hstring GetDeviceSelector() const;
    Windows::Networking::Proximity::ProximityDevice GetDefault() const;
    Windows::Networking::Proximity::ProximityDevice FromId(param::hstring const& deviceId) const;
};
template <> struct consume<Windows::Networking::Proximity::IProximityDeviceStatics> { template <typename D> using type = consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_IProximityMessage
{
    hstring MessageType() const;
    int64_t SubscriptionId() const;
    Windows::Storage::Streams::IBuffer Data() const;
    hstring DataAsString() const;
};
template <> struct consume<Windows::Networking::Proximity::IProximityMessage> { template <typename D> using type = consume_Windows_Networking_Proximity_IProximityMessage<D>; };

template <typename D>
struct consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs
{
    Windows::Networking::Proximity::TriggeredConnectState State() const;
    uint32_t Id() const;
    Windows::Networking::Sockets::StreamSocket Socket() const;
};
template <> struct consume<Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> { template <typename D> using type = consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>; };

}
