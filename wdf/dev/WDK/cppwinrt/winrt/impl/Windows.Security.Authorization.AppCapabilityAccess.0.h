// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess {

enum class AppCapabilityAccessStatus : int32_t
{
    DeniedBySystem = 0,
    NotDeclaredByApp = 1,
    DeniedByUser = 2,
    UserPromptRequired = 3,
    Allowed = 4,
};

struct IAppCapability;
struct IAppCapabilityAccessChangedEventArgs;
struct IAppCapabilityStatics;
struct AppCapability;
struct AppCapabilityAccessChangedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>{ using type = interface_category; };
template <> struct category<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Authorization::AppCapabilityAccess::AppCapability>{ using type = class_category; };
template <> struct category<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>{ using type = enum_category; };
template <> struct name<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>{ static constexpr auto & value{ L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapability" }; };
template <> struct name<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>{ static constexpr auto & value{ L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapabilityAccessChangedEventArgs" }; };
template <> struct name<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>{ static constexpr auto & value{ L"Windows.Security.Authorization.AppCapabilityAccess.IAppCapabilityStatics" }; };
template <> struct name<Windows::Security::Authorization::AppCapabilityAccess::AppCapability>{ static constexpr auto & value{ L"Windows.Security.Authorization.AppCapabilityAccess.AppCapability" }; };
template <> struct name<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs>{ static constexpr auto & value{ L"Windows.Security.Authorization.AppCapabilityAccess.AppCapabilityAccessChangedEventArgs" }; };
template <> struct name<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>{ static constexpr auto & value{ L"Windows.Security.Authorization.AppCapabilityAccess.AppCapabilityAccessStatus" }; };
template <> struct guid_storage<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>{ static constexpr guid value{ 0x4C49D915,0x8A2A,0x4295,{ 0x94,0x37,0x2D,0xF7,0xC3,0x96,0xAF,0xF4 } }; };
template <> struct guid_storage<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>{ static constexpr guid value{ 0x0A578D15,0xBDD7,0x457E,{ 0x8C,0xCA,0x6F,0x53,0xBD,0x2E,0x59,0x44 } }; };
template <> struct guid_storage<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>{ static constexpr guid value{ 0x7C353E2A,0x46EE,0x44E5,{ 0xAF,0x3D,0x6A,0xD3,0xFC,0x49,0xBD,0x22 } }; };
template <> struct default_interface<Windows::Security::Authorization::AppCapabilityAccess::AppCapability>{ using type = Windows::Security::Authorization::AppCapabilityAccess::IAppCapability; };
template <> struct default_interface<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs>{ using type = Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs; };

template <> struct abi<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CapabilityName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CheckAccess(Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus* result) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccessChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccessChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAccessForCapabilitiesAsync(void* capabilityNames, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessForCapabilitiesForUserAsync(void* user, void* capabilityNames, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL Create(void* capabilityName, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithProcessIdForUser(void* user, void* capabilityName, uint32_t pid, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability
{
    hstring CapabilityName() const;
    Windows::System::User User() const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus> RequestAccessAsync() const;
    Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus CheckAccess() const;
    winrt::event_token AccessChanged(Windows::Foundation::TypedEventHandler<Windows::Security::Authorization::AppCapabilityAccess::AppCapability, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const;
    using AccessChanged_revoker = impl::event_revoker<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability, &impl::abi_t<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>::remove_AccessChanged>;
    AccessChanged_revoker AccessChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Security::Authorization::AppCapabilityAccess::AppCapability, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const;
    void AccessChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> { template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>; };

template <typename D>
struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityAccessChangedEventArgs
{
};
template <> struct consume<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> { template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityAccessChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> RequestAccessForCapabilitiesForUserAsync(Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames) const;
    Windows::Security::Authorization::AppCapabilityAccess::AppCapability Create(param::hstring const& capabilityName) const;
    Windows::Security::Authorization::AppCapabilityAccess::AppCapability CreateWithProcessIdForUser(Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid) const;
};
template <> struct consume<Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> { template <typename D> using type = consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>; };

}
