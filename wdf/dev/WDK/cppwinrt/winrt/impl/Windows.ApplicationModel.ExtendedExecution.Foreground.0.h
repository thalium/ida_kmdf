// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution::Foreground {

enum class ExtendedExecutionForegroundReason : int32_t
{
    Unspecified = 0,
    SavingData = 1,
    BackgroundAudio = 2,
    Unconstrained = 3,
};

enum class ExtendedExecutionForegroundResult : int32_t
{
    Allowed = 0,
    Denied = 1,
};

enum class ExtendedExecutionForegroundRevokedReason : int32_t
{
    Resumed = 0,
    SystemPolicy = 1,
};

struct IExtendedExecutionForegroundRevokedEventArgs;
struct IExtendedExecutionForegroundSession;
struct ExtendedExecutionForegroundRevokedEventArgs;
struct ExtendedExecutionForegroundSession;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundSession>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.IExtendedExecutionForegroundRevokedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.IExtendedExecutionForegroundSession" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.ExtendedExecutionForegroundRevokedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundSession>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.ExtendedExecutionForegroundSession" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.ExtendedExecutionForegroundReason" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.ExtendedExecutionForegroundResult" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.Foreground.ExtendedExecutionForegroundRevokedReason" }; };
template <> struct guid_storage<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs>{ static constexpr guid value{ 0xB07CD940,0x9557,0xAEA4,{ 0x2C,0x99,0xBD,0xD5,0x6D,0x9B,0xE4,0x61 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession>{ static constexpr guid value{ 0xFBF440E1,0x9D10,0x4201,{ 0xB0,0x1E,0xC8,0x32,0x75,0x29,0x6F,0x2E } }; };
template <> struct default_interface<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs>{ using type = Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundSession>{ using type = Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession; };

template <> struct abi<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Revoked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Revoked(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL RequestExtensionAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundRevokedEventArgs
{
    Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason Reason() const;
};
template <> struct consume<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundRevokedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession
{
    hstring Description() const;
    void Description(param::hstring const& value) const;
    winrt::event_token Revoked(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> const& handler) const;
    using Revoked_revoker = impl::event_revoker<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession, &impl::abi_t<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession>::remove_Revoked>;
    Revoked_revoker Revoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> const& handler) const;
    void Revoked(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult> RequestExtensionAsync() const;
    Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason Reason() const;
    void Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason const& value) const;
};
template <> struct consume<Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession> { template <typename D> using type = consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>; };

}
