// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Networking::Connectivity {

struct IPInformation;

}

WINRT_EXPORT namespace winrt::Windows::Networking {

enum class DomainNameType : int32_t
{
    Suffix = 0,
    FullyQualified = 1,
};

enum class HostNameSortOptions : uint32_t
{
    None = 0x0,
    OptimizeForLongConnections = 0x2,
};

enum class HostNameType : int32_t
{
    DomainName = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Bluetooth = 3,
};

struct IEndpointPair;
struct IEndpointPairFactory;
struct IHostName;
struct IHostNameFactory;
struct IHostNameStatics;
struct EndpointPair;
struct HostName;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Networking::HostNameSortOptions> : std::true_type {};
template <> struct category<Windows::Networking::IEndpointPair>{ using type = interface_category; };
template <> struct category<Windows::Networking::IEndpointPairFactory>{ using type = interface_category; };
template <> struct category<Windows::Networking::IHostName>{ using type = interface_category; };
template <> struct category<Windows::Networking::IHostNameFactory>{ using type = interface_category; };
template <> struct category<Windows::Networking::IHostNameStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::EndpointPair>{ using type = class_category; };
template <> struct category<Windows::Networking::HostName>{ using type = class_category; };
template <> struct category<Windows::Networking::DomainNameType>{ using type = enum_category; };
template <> struct category<Windows::Networking::HostNameSortOptions>{ using type = enum_category; };
template <> struct category<Windows::Networking::HostNameType>{ using type = enum_category; };
template <> struct name<Windows::Networking::IEndpointPair>{ static constexpr auto & value{ L"Windows.Networking.IEndpointPair" }; };
template <> struct name<Windows::Networking::IEndpointPairFactory>{ static constexpr auto & value{ L"Windows.Networking.IEndpointPairFactory" }; };
template <> struct name<Windows::Networking::IHostName>{ static constexpr auto & value{ L"Windows.Networking.IHostName" }; };
template <> struct name<Windows::Networking::IHostNameFactory>{ static constexpr auto & value{ L"Windows.Networking.IHostNameFactory" }; };
template <> struct name<Windows::Networking::IHostNameStatics>{ static constexpr auto & value{ L"Windows.Networking.IHostNameStatics" }; };
template <> struct name<Windows::Networking::EndpointPair>{ static constexpr auto & value{ L"Windows.Networking.EndpointPair" }; };
template <> struct name<Windows::Networking::HostName>{ static constexpr auto & value{ L"Windows.Networking.HostName" }; };
template <> struct name<Windows::Networking::DomainNameType>{ static constexpr auto & value{ L"Windows.Networking.DomainNameType" }; };
template <> struct name<Windows::Networking::HostNameSortOptions>{ static constexpr auto & value{ L"Windows.Networking.HostNameSortOptions" }; };
template <> struct name<Windows::Networking::HostNameType>{ static constexpr auto & value{ L"Windows.Networking.HostNameType" }; };
template <> struct guid_storage<Windows::Networking::IEndpointPair>{ static constexpr guid value{ 0x33A0AA36,0xF8FA,0x4B30,{ 0xB8,0x56,0x76,0x51,0x7C,0x3B,0xD0,0x6D } }; };
template <> struct guid_storage<Windows::Networking::IEndpointPairFactory>{ static constexpr guid value{ 0xB609D971,0x64E0,0x442B,{ 0xAA,0x6F,0xCC,0x8C,0x8F,0x18,0x1F,0x78 } }; };
template <> struct guid_storage<Windows::Networking::IHostName>{ static constexpr guid value{ 0xBF8ECAAD,0xED96,0x49A7,{ 0x90,0x84,0xD4,0x16,0xCA,0xE8,0x8D,0xCB } }; };
template <> struct guid_storage<Windows::Networking::IHostNameFactory>{ static constexpr guid value{ 0x458C23ED,0x712F,0x4576,{ 0xAD,0xF1,0xC2,0x0B,0x2C,0x64,0x35,0x58 } }; };
template <> struct guid_storage<Windows::Networking::IHostNameStatics>{ static constexpr guid value{ 0xF68CD4BF,0xA388,0x4E8B,{ 0x91,0xEA,0x54,0xDD,0x6D,0xD9,0x01,0xC0 } }; };
template <> struct default_interface<Windows::Networking::EndpointPair>{ using type = Windows::Networking::IEndpointPair; };
template <> struct default_interface<Windows::Networking::HostName>{ using type = Windows::Networking::IHostName; };

template <> struct abi<Windows::Networking::IEndpointPair>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LocalHostName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LocalHostName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocalServiceName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LocalServiceName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteHostName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteHostName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteServiceName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteServiceName(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::IEndpointPairFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateEndpointPair(void* localHostName, void* localServiceName, void* remoteHostName, void* remoteServiceName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::IHostName>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IPInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RawName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanonicalName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(Windows::Networking::HostNameType* value) noexcept = 0;
    virtual int32_t WINRT_CALL IsEqual(void* hostName, bool* isEqual) noexcept = 0;
};};

template <> struct abi<Windows::Networking::IHostNameFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateHostName(void* hostName, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::IHostNameStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Compare(void* value1, void* value2, int32_t* result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Networking_IEndpointPair
{
    Windows::Networking::HostName LocalHostName() const;
    void LocalHostName(Windows::Networking::HostName const& value) const;
    hstring LocalServiceName() const;
    void LocalServiceName(param::hstring const& value) const;
    Windows::Networking::HostName RemoteHostName() const;
    void RemoteHostName(Windows::Networking::HostName const& value) const;
    hstring RemoteServiceName() const;
    void RemoteServiceName(param::hstring const& value) const;
};
template <> struct consume<Windows::Networking::IEndpointPair> { template <typename D> using type = consume_Windows_Networking_IEndpointPair<D>; };

template <typename D>
struct consume_Windows_Networking_IEndpointPairFactory
{
    Windows::Networking::EndpointPair CreateEndpointPair(Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName, Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const;
};
template <> struct consume<Windows::Networking::IEndpointPairFactory> { template <typename D> using type = consume_Windows_Networking_IEndpointPairFactory<D>; };

template <typename D>
struct consume_Windows_Networking_IHostName
{
    Windows::Networking::Connectivity::IPInformation IPInformation() const;
    hstring RawName() const;
    hstring DisplayName() const;
    hstring CanonicalName() const;
    Windows::Networking::HostNameType Type() const;
    bool IsEqual(Windows::Networking::HostName const& hostName) const;
};
template <> struct consume<Windows::Networking::IHostName> { template <typename D> using type = consume_Windows_Networking_IHostName<D>; };

template <typename D>
struct consume_Windows_Networking_IHostNameFactory
{
    Windows::Networking::HostName CreateHostName(param::hstring const& hostName) const;
};
template <> struct consume<Windows::Networking::IHostNameFactory> { template <typename D> using type = consume_Windows_Networking_IHostNameFactory<D>; };

template <typename D>
struct consume_Windows_Networking_IHostNameStatics
{
    int32_t Compare(param::hstring const& value1, param::hstring const& value2) const;
};
template <> struct consume<Windows::Networking::IHostNameStatics> { template <typename D> using type = consume_Windows_Networking_IHostNameStatics<D>; };

}
