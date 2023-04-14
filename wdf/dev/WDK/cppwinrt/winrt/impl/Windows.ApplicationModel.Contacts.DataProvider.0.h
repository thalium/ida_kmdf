// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts {

enum class ContactBatchStatus;
struct Contact;
struct ContactQueryOptions;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::DataProvider {

struct IContactDataProviderConnection;
struct IContactDataProviderConnection2;
struct IContactDataProviderTriggerDetails;
struct IContactListCreateOrUpdateContactRequest;
struct IContactListCreateOrUpdateContactRequestEventArgs;
struct IContactListDeleteContactRequest;
struct IContactListDeleteContactRequestEventArgs;
struct IContactListServerSearchReadBatchRequest;
struct IContactListServerSearchReadBatchRequestEventArgs;
struct IContactListSyncManagerSyncRequest;
struct IContactListSyncManagerSyncRequestEventArgs;
struct ContactDataProviderConnection;
struct ContactDataProviderTriggerDetails;
struct ContactListCreateOrUpdateContactRequest;
struct ContactListCreateOrUpdateContactRequestEventArgs;
struct ContactListDeleteContactRequest;
struct ContactListDeleteContactRequestEventArgs;
struct ContactListServerSearchReadBatchRequest;
struct ContactListServerSearchReadBatchRequestEventArgs;
struct ContactListSyncManagerSyncRequest;
struct ContactListSyncManagerSyncRequestEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs>{ using type = class_category; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactDataProviderConnection" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactDataProviderConnection2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactDataProviderTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListCreateOrUpdateContactRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListCreateOrUpdateContactRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListDeleteContactRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListDeleteContactRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListServerSearchReadBatchRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListServerSearchReadBatchRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListSyncManagerSyncRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.IContactListSyncManagerSyncRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactDataProviderConnection" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderTriggerDetails>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactDataProviderTriggerDetails" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListCreateOrUpdateContactRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListCreateOrUpdateContactRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListDeleteContactRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListDeleteContactRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListServerSearchReadBatchRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListServerSearchReadBatchRequestEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListSyncManagerSyncRequest" }; };
template <> struct name<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.DataProvider.ContactListSyncManagerSyncRequestEventArgs" }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>{ static constexpr guid value{ 0x1A398A52,0x8C9D,0x4D6F,{ 0xA4,0xE0,0x11,0x1E,0x9A,0x12,0x5A,0x30 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>{ static constexpr guid value{ 0xA1D327B0,0x196C,0x4BFD,{ 0x8F,0x0F,0xC6,0x8D,0x67,0xF2,0x49,0xD3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails>{ static constexpr guid value{ 0x527104BE,0x3C62,0x43C8,{ 0x9A,0xE7,0xDB,0x53,0x16,0x85,0xCD,0x99 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest>{ static constexpr guid value{ 0xB4AF411F,0xC849,0x47D0,{ 0xB1,0x19,0x91,0xCF,0x60,0x5B,0x2F,0x2A } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs>{ static constexpr guid value{ 0x851C1690,0x1A51,0x4B0C,{ 0xAE,0xEF,0x12,0x40,0xAC,0x5B,0xED,0x75 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest>{ static constexpr guid value{ 0x5E114687,0xCE03,0x4DE5,{ 0x85,0x57,0x9C,0xCF,0x55,0x2D,0x47,0x2A } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs>{ static constexpr guid value{ 0xB22054A1,0xE8FA,0x4DB5,{ 0x93,0x89,0x2D,0x12,0xEE,0x7D,0x15,0xEE } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest>{ static constexpr guid value{ 0xBA776A97,0x4030,0x4925,{ 0x9F,0xB4,0x14,0x3B,0x29,0x5E,0x65,0x3B } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs>{ static constexpr guid value{ 0x1A27E87B,0x69D7,0x4E4E,{ 0x80,0x42,0x86,0x1C,0xBA,0x61,0x47,0x1E } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest>{ static constexpr guid value{ 0x3C0E57A4,0xC4E7,0x4970,{ 0x9A,0x8F,0x9A,0x66,0xA2,0xBB,0x6C,0x1A } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs>{ static constexpr guid value{ 0x158E4DAC,0x446D,0x4F10,{ 0xAF,0xC2,0x02,0x68,0x3E,0xC5,0x33,0xA6 } }; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderTriggerDetails>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs>{ using type = Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs; };

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SyncRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SyncRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ServerSearchReadBatchRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ServerSearchReadBatchRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_CreateOrUpdateContactRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CreateOrUpdateContactRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DeleteContactRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DeleteContactRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Connection(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Contact(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompletedAsync(void* createdOrUpdatedContact, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContactId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SessionId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContactListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Options(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SuggestedBatchSize(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveContactAsync(void* contact, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReportFailedAsync(Windows::ApplicationModel::Contacts::ContactBatchStatus batchStatus, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContactListId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection
{
    winrt::event_token SyncRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> const& handler) const;
    using SyncRequested_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection, &impl::abi_t<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>::remove_SyncRequested>;
    SyncRequested_revoker SyncRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> const& handler) const;
    void SyncRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token ServerSearchReadBatchRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> const& handler) const;
    using ServerSearchReadBatchRequested_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection, &impl::abi_t<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>::remove_ServerSearchReadBatchRequested>;
    ServerSearchReadBatchRequested_revoker ServerSearchReadBatchRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> const& handler) const;
    void ServerSearchReadBatchRequested(winrt::event_token const& token) const noexcept;
    void Start() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2
{
    winrt::event_token CreateOrUpdateContactRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> const& handler) const;
    using CreateOrUpdateContactRequested_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2, &impl::abi_t<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>::remove_CreateOrUpdateContactRequested>;
    CreateOrUpdateContactRequested_revoker CreateOrUpdateContactRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> const& handler) const;
    void CreateOrUpdateContactRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token DeleteContactRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> const& handler) const;
    using DeleteContactRequested_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2, &impl::abi_t<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>::remove_DeleteContactRequested>;
    DeleteContactRequested_revoker DeleteContactRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> const& handler) const;
    void DeleteContactRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderTriggerDetails
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection Connection() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderTriggerDetails<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequest
{
    hstring ContactListId() const;
    Windows::ApplicationModel::Contacts::Contact Contact() const;
    Windows::Foundation::IAsyncAction ReportCompletedAsync(Windows::ApplicationModel::Contacts::Contact const& createdOrUpdatedContact) const;
    Windows::Foundation::IAsyncAction ReportFailedAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequestEventArgs
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest Request() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequestEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequest
{
    hstring ContactListId() const;
    hstring ContactId() const;
    Windows::Foundation::IAsyncAction ReportCompletedAsync() const;
    Windows::Foundation::IAsyncAction ReportFailedAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequestEventArgs
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest Request() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequestEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest
{
    hstring SessionId() const;
    hstring ContactListId() const;
    Windows::ApplicationModel::Contacts::ContactQueryOptions Options() const;
    uint32_t SuggestedBatchSize() const;
    Windows::Foundation::IAsyncAction SaveContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::IAsyncAction ReportCompletedAsync() const;
    Windows::Foundation::IAsyncAction ReportFailedAsync(Windows::ApplicationModel::Contacts::ContactBatchStatus const& batchStatus) const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequestEventArgs
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest Request() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequestEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequest
{
    hstring ContactListId() const;
    Windows::Foundation::IAsyncAction ReportCompletedAsync() const;
    Windows::Foundation::IAsyncAction ReportFailedAsync() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequestEventArgs
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest Request() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequestEventArgs<D>; };

}
