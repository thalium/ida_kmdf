// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts {

enum class UserDataAccountContentKinds : unsigned;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::Provider {

enum class UserDataAccountProviderOperationKind : int32_t
{
    AddAccount = 0,
    Settings = 1,
    ResolveErrors = 2,
};

enum class UserDataAccountProviderPartnerAccountKind : int32_t
{
    Exchange = 0,
    PopOrImap = 1,
};

struct IUserDataAccountPartnerAccountInfo;
struct IUserDataAccountProviderAddAccountOperation;
struct IUserDataAccountProviderOperation;
struct IUserDataAccountProviderResolveErrorsOperation;
struct IUserDataAccountProviderSettingsOperation;
struct UserDataAccountPartnerAccountInfo;
struct UserDataAccountProviderAddAccountOperation;
struct UserDataAccountProviderResolveErrorsOperation;
struct UserDataAccountProviderSettingsOperation;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderAddAccountOperation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderResolveErrorsOperation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderSettingsOperation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.IUserDataAccountPartnerAccountInfo" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.IUserDataAccountProviderAddAccountOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.IUserDataAccountProviderOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.IUserDataAccountProviderResolveErrorsOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.IUserDataAccountProviderSettingsOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.UserDataAccountPartnerAccountInfo" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderAddAccountOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.UserDataAccountProviderAddAccountOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderResolveErrorsOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.UserDataAccountProviderResolveErrorsOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderSettingsOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.UserDataAccountProviderSettingsOperation" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.UserDataAccountProviderOperationKind" }; };
template <> struct name<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.UserDataAccounts.Provider.UserDataAccountProviderPartnerAccountKind" }; };
template <> struct guid_storage<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo>{ static constexpr guid value{ 0x5F200037,0xF6EF,0x4EC3,{ 0x86,0x30,0x01,0x2C,0x59,0xC1,0x14,0x9F } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation>{ static constexpr guid value{ 0xB9C72530,0x3F84,0x4B5D,{ 0x8E,0xAA,0x45,0xE9,0x7A,0xA8,0x42,0xED } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation>{ static constexpr guid value{ 0xA20AAD63,0x888C,0x4A62,{ 0xA3,0xDD,0x34,0xD0,0x7A,0x80,0x2B,0x2B } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation>{ static constexpr guid value{ 0x6235DC15,0xBFCB,0x41E1,{ 0x99,0x57,0x97,0x59,0xA2,0x88,0x46,0xCC } }; };
template <> struct guid_storage<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation>{ static constexpr guid value{ 0x92034DB7,0x8648,0x4F30,{ 0xAC,0xFA,0x30,0x02,0x65,0x8C,0xA8,0x0D } }; };
template <> struct default_interface<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo>{ using type = Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo; };
template <> struct default_interface<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderAddAccountOperation>{ using type = Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation; };
template <> struct default_interface<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderResolveErrorsOperation>{ using type = Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation; };
template <> struct default_interface<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderSettingsOperation>{ using type = Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation; };

template <> struct abi<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Priority(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccountKind(Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentKinds(Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PartnerAccountInfos(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompleted(void* userDataAccountId) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompleted() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompleted() noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountPartnerAccountInfo
{
    hstring DisplayName() const;
    uint32_t Priority() const;
    Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind AccountKind() const;
};
template <> struct consume<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo> { template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountPartnerAccountInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderAddAccountOperation
{
    Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds ContentKinds() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo> PartnerAccountInfos() const;
    void ReportCompleted(param::hstring const& userDataAccountId) const;
};
template <> struct consume<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation> { template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderAddAccountOperation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderOperation
{
    Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind Kind() const;
};
template <> struct consume<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation> { template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderOperation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderResolveErrorsOperation
{
    hstring UserDataAccountId() const;
    void ReportCompleted() const;
};
template <> struct consume<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation> { template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderResolveErrorsOperation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderSettingsOperation
{
    hstring UserDataAccountId() const;
    void ReportCompleted() const;
};
template <> struct consume<Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation> { template <typename D> using type = consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderSettingsOperation<D>; };

}
