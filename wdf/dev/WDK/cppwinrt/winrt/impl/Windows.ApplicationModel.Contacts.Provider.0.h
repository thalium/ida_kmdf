// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts {

enum class ContactFieldType;
enum class ContactSelectionMode;
struct Contact;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::Provider {

enum class AddContactResult : int32_t
{
    Added = 0,
    AlreadyAdded = 1,
    Unavailable = 2,
};

struct IContactPickerUI;
struct IContactPickerUI2;
struct IContactRemovedEventArgs;
struct ContactPickerUI;
struct ContactRemovedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Contacts::Provider::AddContactResult>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Provider.IContactPickerUI" }; };
template <> struct name<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Provider.IContactPickerUI2" }; };
template <> struct name<Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Provider.IContactRemovedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Provider.ContactPickerUI" }; };
template <> struct name<Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Provider.ContactRemovedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::Contacts::Provider::AddContactResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.Contacts.Provider.AddContactResult" }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>{ static constexpr guid value{ 0xE2CC1366,0xCF66,0x43C4,{ 0xA9,0x6A,0xA5,0xA1,0x12,0xDB,0x47,0x46 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>{ static constexpr guid value{ 0x6E449E28,0x7B25,0x4999,{ 0x9B,0x0B,0x87,0x54,0x00,0xA1,0xE8,0xC8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>{ static constexpr guid value{ 0x6F354338,0x3302,0x4D13,{ 0xAD,0x8D,0xAD,0xCC,0x0F,0xF9,0xE4,0x7C } }; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI>{ using type = Windows::ApplicationModel::Contacts::Provider::IContactPickerUI; };
template <> struct default_interface<Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs>{ using type = Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs; };

template <> struct abi<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddContact(void* id, void* contact, Windows::ApplicationModel::Contacts::Provider::AddContactResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveContact(void* id) noexcept = 0;
    virtual int32_t WINRT_CALL ContainsContact(void* id, bool* isContained) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredFields(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ContactRemoved(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ContactRemoved(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddContact(void* contact, Windows::ApplicationModel::Contacts::Provider::AddContactResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredFieldsWithContactFieldType(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI
{
    Windows::ApplicationModel::Contacts::Provider::AddContactResult AddContact(param::hstring const& id, Windows::ApplicationModel::Contacts::Contact const& contact) const;
    void RemoveContact(param::hstring const& id) const;
    bool ContainsContact(param::hstring const& id) const;
    Windows::Foundation::Collections::IVectorView<hstring> DesiredFields() const;
    Windows::ApplicationModel::Contacts::ContactSelectionMode SelectionMode() const;
    winrt::event_token ContactRemoved(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const;
    using ContactRemoved_revoker = impl::event_revoker<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI, &impl::abi_t<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>::remove_ContactRemoved>;
    ContactRemoved_revoker ContactRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const;
    void ContactRemoved(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2
{
    Windows::ApplicationModel::Contacts::Provider::AddContactResult AddContact(Windows::ApplicationModel::Contacts::Contact const& contact) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType> DesiredFieldsWithContactFieldType() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_Contacts_Provider_IContactRemovedEventArgs
{
    hstring Id() const;
};
template <> struct consume<Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_Contacts_Provider_IContactRemovedEventArgs<D>; };

}
