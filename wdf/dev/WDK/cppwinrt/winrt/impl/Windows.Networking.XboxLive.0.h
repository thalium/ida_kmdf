// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Networking {

struct HostName;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Networking::XboxLive {

enum class XboxLiveEndpointPairCreationBehaviors : uint32_t
{
    None = 0x0,
    ReevaluatePath = 0x1,
};

enum class XboxLiveEndpointPairCreationStatus : int32_t
{
    Succeeded = 0,
    NoLocalNetworks = 1,
    NoCompatibleNetworkPaths = 2,
    LocalSystemNotAuthorized = 3,
    Canceled = 4,
    TimedOut = 5,
    RemoteSystemNotAuthorized = 6,
    RefusedDueToConfiguration = 7,
    UnexpectedInternalError = 8,
};

enum class XboxLiveEndpointPairState : int32_t
{
    Invalid = 0,
    CreatingOutbound = 1,
    CreatingInbound = 2,
    Ready = 3,
    DeletingLocally = 4,
    RemoteEndpointTerminating = 5,
    Deleted = 6,
};

enum class XboxLiveNetworkAccessKind : int32_t
{
    Open = 0,
    Moderate = 1,
    Strict = 2,
};

enum class XboxLiveQualityOfServiceMeasurementStatus : int32_t
{
    NotStarted = 0,
    InProgress = 1,
    InProgressWithProvisionalResults = 2,
    Succeeded = 3,
    NoLocalNetworks = 4,
    NoCompatibleNetworkPaths = 5,
    LocalSystemNotAuthorized = 6,
    Canceled = 7,
    TimedOut = 8,
    RemoteSystemNotAuthorized = 9,
    RefusedDueToConfiguration = 10,
    UnexpectedInternalError = 11,
};

enum class XboxLiveQualityOfServiceMetric : int32_t
{
    AverageLatencyInMilliseconds = 0,
    MinLatencyInMilliseconds = 1,
    MaxLatencyInMilliseconds = 2,
    AverageOutboundBitsPerSecond = 3,
    MinOutboundBitsPerSecond = 4,
    MaxOutboundBitsPerSecond = 5,
    AverageInboundBitsPerSecond = 6,
    MinInboundBitsPerSecond = 7,
    MaxInboundBitsPerSecond = 8,
};

enum class XboxLiveSocketKind : int32_t
{
    None = 0,
    Datagram = 1,
    Stream = 2,
};

struct IXboxLiveDeviceAddress;
struct IXboxLiveDeviceAddressStatics;
struct IXboxLiveEndpointPair;
struct IXboxLiveEndpointPairCreationResult;
struct IXboxLiveEndpointPairStateChangedEventArgs;
struct IXboxLiveEndpointPairStatics;
struct IXboxLiveEndpointPairTemplate;
struct IXboxLiveEndpointPairTemplateStatics;
struct IXboxLiveInboundEndpointPairCreatedEventArgs;
struct IXboxLiveQualityOfServiceMeasurement;
struct IXboxLiveQualityOfServiceMeasurementStatics;
struct IXboxLiveQualityOfServiceMetricResult;
struct IXboxLiveQualityOfServicePrivatePayloadResult;
struct XboxLiveDeviceAddress;
struct XboxLiveEndpointPair;
struct XboxLiveEndpointPairCreationResult;
struct XboxLiveEndpointPairStateChangedEventArgs;
struct XboxLiveEndpointPairTemplate;
struct XboxLiveInboundEndpointPairCreatedEventArgs;
struct XboxLiveQualityOfServiceMeasurement;
struct XboxLiveQualityOfServiceMetricResult;
struct XboxLiveQualityOfServicePrivatePayloadResult;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors> : std::true_type {};
template <> struct category<Windows::Networking::XboxLive::IXboxLiveDeviceAddress>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveEndpointPair>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveDeviceAddress>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPair>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurement>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult>{ using type = class_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors>{ using type = enum_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveEndpointPairState>{ using type = enum_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveNetworkAccessKind>{ using type = enum_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric>{ using type = enum_category; };
template <> struct category<Windows::Networking::XboxLive::XboxLiveSocketKind>{ using type = enum_category; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveDeviceAddress>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveDeviceAddress" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveDeviceAddressStatics" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveEndpointPair>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveEndpointPair" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveEndpointPairCreationResult" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveEndpointPairStateChangedEventArgs" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveEndpointPairStatics" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveEndpointPairTemplate" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveEndpointPairTemplateStatics" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveInboundEndpointPairCreatedEventArgs" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveQualityOfServiceMeasurement" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveQualityOfServiceMeasurementStatics" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveQualityOfServiceMetricResult" }; };
template <> struct name<Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.IXboxLiveQualityOfServicePrivatePayloadResult" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveDeviceAddress>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveDeviceAddress" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPair>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPair" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPairCreationResult" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPairStateChangedEventArgs" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPairTemplate" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveInboundEndpointPairCreatedEventArgs" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurement>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveQualityOfServiceMeasurement" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveQualityOfServiceMetricResult" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveQualityOfServicePrivatePayloadResult" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPairCreationBehaviors" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPairCreationStatus" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveEndpointPairState>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveEndpointPairState" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveNetworkAccessKind>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveNetworkAccessKind" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveQualityOfServiceMeasurementStatus" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveQualityOfServiceMetric" }; };
template <> struct name<Windows::Networking::XboxLive::XboxLiveSocketKind>{ static constexpr auto & value{ L"Windows.Networking.XboxLive.XboxLiveSocketKind" }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveDeviceAddress>{ static constexpr guid value{ 0xF5BBD279,0x3C86,0x4B57,{ 0xA3,0x1A,0xB9,0x46,0x24,0x08,0xFD,0x01 } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>{ static constexpr guid value{ 0x5954A819,0x4A79,0x4931,{ 0x82,0x7C,0x7F,0x50,0x3E,0x96,0x32,0x63 } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveEndpointPair>{ static constexpr guid value{ 0x1E9A839B,0x813E,0x44E0,{ 0xB8,0x7F,0xC8,0x7A,0x09,0x34,0x75,0xE4 } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult>{ static constexpr guid value{ 0xD9A8BB95,0x2AAB,0x4D1E,{ 0x97,0x94,0x33,0xEC,0xC0,0xDC,0xF0,0xFE } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs>{ static constexpr guid value{ 0x592E3B55,0xDE08,0x44E7,{ 0xAC,0x3B,0xB9,0xB9,0xA1,0x69,0x58,0x3A } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>{ static constexpr guid value{ 0x64316B30,0x217A,0x4243,{ 0x8E,0xE1,0x67,0x29,0x28,0x1D,0x27,0xDB } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate>{ static constexpr guid value{ 0x6B286ECF,0x3457,0x40CE,{ 0xB9,0xA1,0xC0,0xCF,0xE0,0x21,0x3E,0xA7 } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>{ static constexpr guid value{ 0x1E13137B,0x737B,0x4A23,{ 0xBC,0x64,0x08,0x70,0xF7,0x56,0x55,0xBA } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs>{ static constexpr guid value{ 0xDC183B62,0x22BA,0x48D2,{ 0x80,0xDE,0xC2,0x39,0x68,0xBD,0x19,0x8B } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement>{ static constexpr guid value{ 0x4D682BCE,0xA5D6,0x47E6,{ 0xA2,0x36,0xCF,0xDE,0x5F,0xBD,0xF2,0xED } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>{ static constexpr guid value{ 0x6E352DCA,0x23CF,0x440A,{ 0xB0,0x77,0x5E,0x30,0x85,0x7A,0x82,0x34 } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult>{ static constexpr guid value{ 0xAEEC53D1,0x3561,0x4782,{ 0xB0,0xCF,0xD3,0xAE,0x29,0xD9,0xFA,0x87 } }; };
template <> struct guid_storage<Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult>{ static constexpr guid value{ 0x5A6302AE,0x6F38,0x41C0,{ 0x9F,0xCC,0xEA,0x6C,0xB9,0x78,0xCA,0xFC } }; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveDeviceAddress>{ using type = Windows::Networking::XboxLive::IXboxLiveDeviceAddress; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveEndpointPair>{ using type = Windows::Networking::XboxLive::IXboxLiveEndpointPair; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>{ using type = Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs>{ using type = Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>{ using type = Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs>{ using type = Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurement>{ using type = Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>{ using type = Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult; };
template <> struct default_interface<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult>{ using type = Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult; };

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveDeviceAddress>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SnapshotChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SnapshotChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetSnapshotAsBase64(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSnapshotAsBuffer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSnapshotAsBytes(uint32_t __bufferSize, uint8_t* buffer, uint32_t* bytesWritten) noexcept = 0;
    virtual int32_t WINRT_CALL Compare(void* otherDeviceAddress, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsValid(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsLocal(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkAccessKind(Windows::Networking::XboxLive::XboxLiveNetworkAccessKind* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromSnapshotBase64(void* base64, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromSnapshotBuffer(void* buffer, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromSnapshotBytes(uint32_t __bufferSize, uint8_t* buffer, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetLocal(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSnapshotBytesSize(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveEndpointPair>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL GetRemoteSocketAddressBytes(uint32_t __socketAddressSize, uint8_t* socketAddress) noexcept = 0;
    virtual int32_t WINRT_CALL GetLocalSocketAddressBytes(uint32_t __socketAddressSize, uint8_t* socketAddress) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Networking::XboxLive::XboxLiveEndpointPairState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Template(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteDeviceAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteHostName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemotePort(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocalHostName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocalPort(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsExistingPathEvaluation(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndpointPair(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldState(Windows::Networking::XboxLive::XboxLiveEndpointPairState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewState(Windows::Networking::XboxLive::XboxLiveEndpointPairState* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindEndpointPairBySocketAddressBytes(uint32_t __localSocketAddressSize, uint8_t* localSocketAddress, uint32_t __remoteSocketAddressSize, uint8_t* remoteSocketAddress, void** endpointPair) noexcept = 0;
    virtual int32_t WINRT_CALL FindEndpointPairByHostNamesAndPorts(void* localHostName, void* localPort, void* remoteHostName, void* remotePort, void** endpointPair) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_InboundEndpointPairCreated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_InboundEndpointPairCreated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL CreateEndpointPairDefaultAsync(void* deviceAddress, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateEndpointPairWithBehaviorsAsync(void* deviceAddress, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors behaviors, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateEndpointPairForPortsDefaultAsync(void* deviceAddress, void* initiatorPort, void* acceptorPort, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateEndpointPairForPortsWithBehaviorsAsync(void* deviceAddress, void* initiatorPort, void* acceptorPort, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors behaviors, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SocketKind(Windows::Networking::XboxLive::XboxLiveSocketKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InitiatorBoundPortRangeLower(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InitiatorBoundPortRangeUpper(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AcceptorBoundPortRangeLower(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AcceptorBoundPortRangeUpper(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndpointPairs(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetTemplateByName(void* name, void** namedTemplate) noexcept = 0;
    virtual int32_t WINRT_CALL get_Templates(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EndpointPair(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL MeasureAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL GetMetricResultsForDevice(void* deviceAddress, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMetricResultsForMetric(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric metric, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMetricResult(void* deviceAddress, Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric metric, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPrivatePayloadResult(void* deviceAddress, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Metrics(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceAddresses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShouldRequestPrivatePayloads(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ShouldRequestPrivatePayloads(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeoutInMilliseconds(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TimeoutInMilliseconds(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfProbesToAttempt(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NumberOfProbesToAttempt(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumberOfResultsPending(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MetricResults(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrivatePayloadResults(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL PublishPrivatePayloadBytes(uint32_t __payloadSize, uint8_t* payload) noexcept = 0;
    virtual int32_t WINRT_CALL ClearPrivatePayload() noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSimultaneousProbeConnections(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxSimultaneousProbeConnections(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSystemOutboundBandwidthConstrained(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsSystemOutboundBandwidthConstrained(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSystemInboundBandwidthConstrained(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsSystemInboundBandwidthConstrained(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PublishedPrivatePayload(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PublishedPrivatePayload(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPrivatePayloadSize(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Metric(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(uint64_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress
{
    winrt::event_token SnapshotChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveDeviceAddress, Windows::Foundation::IInspectable> const& handler) const;
    using SnapshotChanged_revoker = impl::event_revoker<Windows::Networking::XboxLive::IXboxLiveDeviceAddress, &impl::abi_t<Windows::Networking::XboxLive::IXboxLiveDeviceAddress>::remove_SnapshotChanged>;
    SnapshotChanged_revoker SnapshotChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveDeviceAddress, Windows::Foundation::IInspectable> const& handler) const;
    void SnapshotChanged(winrt::event_token const& token) const noexcept;
    hstring GetSnapshotAsBase64() const;
    Windows::Storage::Streams::IBuffer GetSnapshotAsBuffer() const;
    void GetSnapshotAsBytes(array_view<uint8_t> buffer, uint32_t& bytesWritten) const;
    int32_t Compare(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& otherDeviceAddress) const;
    bool IsValid() const;
    bool IsLocal() const;
    Windows::Networking::XboxLive::XboxLiveNetworkAccessKind NetworkAccessKind() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveDeviceAddress> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress CreateFromSnapshotBase64(param::hstring const& base64) const;
    Windows::Networking::XboxLive::XboxLiveDeviceAddress CreateFromSnapshotBuffer(Windows::Storage::Streams::IBuffer const& buffer) const;
    Windows::Networking::XboxLive::XboxLiveDeviceAddress CreateFromSnapshotBytes(array_view<uint8_t const> buffer) const;
    Windows::Networking::XboxLive::XboxLiveDeviceAddress GetLocal() const;
    uint32_t MaxSnapshotBytesSize() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair
{
    winrt::event_token StateChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPair, Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::Networking::XboxLive::IXboxLiveEndpointPair, &impl::abi_t<Windows::Networking::XboxLive::IXboxLiveEndpointPair>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPair, Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> const& handler) const;
    void StateChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncAction DeleteAsync() const;
    void GetRemoteSocketAddressBytes(array_view<uint8_t> socketAddress) const;
    void GetLocalSocketAddressBytes(array_view<uint8_t> socketAddress) const;
    Windows::Networking::XboxLive::XboxLiveEndpointPairState State() const;
    Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate Template() const;
    Windows::Networking::XboxLive::XboxLiveDeviceAddress RemoteDeviceAddress() const;
    Windows::Networking::HostName RemoteHostName() const;
    hstring RemotePort() const;
    Windows::Networking::HostName LocalHostName() const;
    hstring LocalPort() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveEndpointPair> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairCreationResult
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress DeviceAddress() const;
    Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus Status() const;
    bool IsExistingPathEvaluation() const;
    Windows::Networking::XboxLive::XboxLiveEndpointPair EndpointPair() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairCreationResult<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStateChangedEventArgs
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairState OldState() const;
    Windows::Networking::XboxLive::XboxLiveEndpointPairState NewState() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStateChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStatics
{
    Windows::Networking::XboxLive::XboxLiveEndpointPair FindEndpointPairBySocketAddressBytes(array_view<uint8_t const> localSocketAddress, array_view<uint8_t const> remoteSocketAddress) const;
    Windows::Networking::XboxLive::XboxLiveEndpointPair FindEndpointPairByHostNamesAndPorts(Windows::Networking::HostName const& localHostName, param::hstring const& localPort, Windows::Networking::HostName const& remoteHostName, param::hstring const& remotePort) const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStatics<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate
{
    winrt::event_token InboundEndpointPairCreated(Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> const& handler) const;
    using InboundEndpointPairCreated_revoker = impl::event_revoker<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate, &impl::abi_t<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate>::remove_InboundEndpointPairCreated>;
    InboundEndpointPairCreated_revoker InboundEndpointPairCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> const& handler) const;
    void InboundEndpointPairCreated(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> CreateEndpointPairAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> CreateEndpointPairAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const& behaviors) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> CreateEndpointPairForPortsAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, param::hstring const& initiatorPort, param::hstring const& acceptorPort) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> CreateEndpointPairForPortsAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, param::hstring const& initiatorPort, param::hstring const& acceptorPort, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const& behaviors) const;
    hstring Name() const;
    Windows::Networking::XboxLive::XboxLiveSocketKind SocketKind() const;
    uint16_t InitiatorBoundPortRangeLower() const;
    uint16_t InitiatorBoundPortRangeUpper() const;
    uint16_t AcceptorBoundPortRangeLower() const;
    uint16_t AcceptorBoundPortRangeUpper() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPair> EndpointPairs() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplateStatics
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate GetTemplateByName(param::hstring const& name) const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate> Templates() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplateStatics<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveInboundEndpointPairCreatedEventArgs
{
    Windows::Networking::XboxLive::XboxLiveEndpointPair EndpointPair() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveInboundEndpointPairCreatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement
{
    Windows::Foundation::IAsyncAction MeasureAsync() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> GetMetricResultsForDevice(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress) const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> GetMetricResultsForMetric(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const& metric) const;
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult GetMetricResult(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const& metric) const;
    Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult GetPrivatePayloadResult(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress) const;
    Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric> Metrics() const;
    Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveDeviceAddress> DeviceAddresses() const;
    bool ShouldRequestPrivatePayloads() const;
    void ShouldRequestPrivatePayloads(bool value) const;
    uint32_t TimeoutInMilliseconds() const;
    void TimeoutInMilliseconds(uint32_t value) const;
    uint32_t NumberOfProbesToAttempt() const;
    void NumberOfProbesToAttempt(uint32_t value) const;
    uint32_t NumberOfResultsPending() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> MetricResults() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult> PrivatePayloadResults() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics
{
    void PublishPrivatePayloadBytes(array_view<uint8_t const> payload) const;
    void ClearPrivatePayload() const;
    uint32_t MaxSimultaneousProbeConnections() const;
    void MaxSimultaneousProbeConnections(uint32_t value) const;
    bool IsSystemOutboundBandwidthConstrained() const;
    void IsSystemOutboundBandwidthConstrained(bool value) const;
    bool IsSystemInboundBandwidthConstrained() const;
    void IsSystemInboundBandwidthConstrained(bool value) const;
    Windows::Storage::Streams::IBuffer PublishedPrivatePayload() const;
    void PublishedPrivatePayload(Windows::Storage::Streams::IBuffer const& value) const;
    uint32_t MaxPrivatePayloadSize() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMetricResult
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus Status() const;
    Windows::Networking::XboxLive::XboxLiveDeviceAddress DeviceAddress() const;
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric Metric() const;
    uint64_t Value() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMetricResult<D>; };

template <typename D>
struct consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServicePrivatePayloadResult
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus Status() const;
    Windows::Networking::XboxLive::XboxLiveDeviceAddress DeviceAddress() const;
    Windows::Storage::Streams::IBuffer Value() const;
};
template <> struct consume<Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult> { template <typename D> using type = consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServicePrivatePayloadResult<D>; };

}
