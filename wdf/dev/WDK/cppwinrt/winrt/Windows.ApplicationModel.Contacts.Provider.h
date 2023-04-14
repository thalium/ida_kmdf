// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.Provider.2.h"
#include "winrt/Windows.ApplicationModel.Contacts.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Contacts::Provider::AddContactResult consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::AddContact(param::hstring const& id, Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::ApplicationModel::Contacts::Provider::AddContactResult result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->AddContact(get_abi(id), get_abi(contact), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::RemoveContact(param::hstring const& id) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->RemoveContact(get_abi(id)));
}

template <typename D> bool consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContainsContact(param::hstring const& id) const
{
    bool isContained{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->ContainsContact(get_abi(id), &isContained));
    return isContained;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::DesiredFields() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->get_DesiredFields(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactSelectionMode consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::SelectionMode() const
{
    Windows::ApplicationModel::Contacts::ContactSelectionMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->get_SelectionMode(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->add_ContactRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved_revoker consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ContactRemoved_revoker>(this, ContactRemoved(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->remove_ContactRemoved(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Contacts::Provider::AddContactResult consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2<D>::AddContact(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::ApplicationModel::Contacts::Provider::AddContactResult result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2)->AddContact(get_abi(contact), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType> consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2<D>::DesiredFieldsWithContactFieldType() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2)->get_DesiredFieldsWithContactFieldType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_Provider_IContactRemovedEventArgs<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs)->get_Id(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> : produce_base<D, Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>
{
    int32_t WINRT_CALL AddContact(void* id, void* contact, Windows::ApplicationModel::Contacts::Provider::AddContactResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddContact, WINRT_WRAP(Windows::ApplicationModel::Contacts::Provider::AddContactResult), hstring const&, Windows::ApplicationModel::Contacts::Contact const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::Provider::AddContactResult>(this->shim().AddContact(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveContact(void* id) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveContact, WINRT_WRAP(void), hstring const&);
            this->shim().RemoveContact(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ContainsContact(void* id, bool* isContained) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainsContact, WINRT_WRAP(bool), hstring const&);
            *isContained = detach_from<bool>(this->shim().ContainsContact(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredFields(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFields, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().DesiredFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionMode(Windows::ApplicationModel::Contacts::ContactSelectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionMode, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactSelectionMode));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactSelectionMode>(this->shim().SelectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContactRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ContactRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContactRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContactRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContactRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> : produce_base<D, Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>
{
    int32_t WINRT_CALL AddContact(void* contact, Windows::ApplicationModel::Contacts::Provider::AddContactResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddContact, WINRT_WRAP(Windows::ApplicationModel::Contacts::Provider::AddContactResult), Windows::ApplicationModel::Contacts::Contact const&);
            *result = detach_from<Windows::ApplicationModel::Contacts::Provider::AddContactResult>(this->shim().AddContact(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredFieldsWithContactFieldType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFieldsWithContactFieldType, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Contacts::ContactFieldType>>(this->shim().DesiredFieldsWithContactFieldType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::Provider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> {};

}
