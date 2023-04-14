// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution {

enum class ExtendedExecutionReason : int32_t
{
    Unspecified = 0,
    LocationTracking = 1,
    SavingData = 2,
};

enum class ExtendedExecutionResult : int32_t
{
    Allowed = 0,
    Denied = 1,
};

enum class ExtendedExecutionRevokedReason : int32_t
{
    Resumed = 0,
    SystemPolicy = 1,
};

struct IExtendedExecutionRevokedEventArgs;
struct IExtendedExecutionSession;
struct ExtendedExecutionRevokedEventArgs;
struct ExtendedExecutionSession;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionSession>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.IExtendedExecutionRevokedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.IExtendedExecutionSession" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.ExtendedExecutionRevokedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionSession>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.ExtendedExecutionSession" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.ExtendedExecutionReason" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.ExtendedExecutionResult" }; };
template <> struct name<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason>{ static constexpr auto & value{ L"Windows.ApplicationModel.ExtendedExecution.ExtendedExecutionRevokedReason" }; };
template <> struct guid_storage<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs>{ static constexpr guid value{ 0xBFBC9F16,0x63B5,0x4C0B,{ 0xAA,0xD6,0x82,0x8A,0xF5,0x37,0x3E,0xC3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>{ static constexpr guid value{ 0xAF908A2D,0x118B,0x48F1,{ 0x93,0x08,0x0C,0x4F,0xC4,0x1E,0x20,0x0F } }; };
template <> struct default_interface<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs>{ using type = Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionSession>{ using type = Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession; };

template <> struct abi<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PercentProgress(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PercentProgress(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Revoked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Revoked(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL RequestExtensionAsync(void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionRevokedEventArgs
{
    Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason Reason() const;
};
template <> struct consume<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionRevokedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession
{
    Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason Reason() const;
    void Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
    uint32_t PercentProgress() const;
    void PercentProgress(uint32_t value) const;
    winrt::event_token Revoked(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const& handler) const;
    using Revoked_revoker = impl::event_revoker<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession, &impl::abi_t<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>::remove_Revoked>;
    Revoked_revoker Revoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const& handler) const;
    void Revoked(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult> RequestExtensionAsync() const;
};
template <> struct consume<Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession> { template <typename D> using type = consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>; };

}
