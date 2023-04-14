// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.Background.2.h"
#include "winrt/Windows.ApplicationModel.Calls.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Background_IPhoneCallBlockedTriggerDetails<D>::PhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails)->get_PhoneNumber(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_Background_IPhoneCallBlockedTriggerDetails<D>::LineId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails)->get_LineId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::Background::PhoneCallBlockedReason consume_Windows_ApplicationModel_Calls_Background_IPhoneCallBlockedTriggerDetails<D>::CallBlockedReason() const
{
    Windows::ApplicationModel::Calls::Background::PhoneCallBlockedReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails)->get_CallBlockedReason(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_Background_IPhoneCallOriginDataRequestTriggerDetails<D>::RequestId() const
{
    winrt::guid result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails)->get_RequestId(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Background_IPhoneCallOriginDataRequestTriggerDetails<D>::PhoneNumber() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails)->get_PhoneNumber(put_abi(result)));
    return result;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_Background_IPhoneIncomingCallDismissedTriggerDetails<D>::LineId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails)->get_LineId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Background_IPhoneIncomingCallDismissedTriggerDetails<D>::PhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails)->get_PhoneNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Background_IPhoneIncomingCallDismissedTriggerDetails<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Calls_Background_IPhoneIncomingCallDismissedTriggerDetails<D>::DismissalTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails)->get_DismissalTime(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Background_IPhoneIncomingCallDismissedTriggerDetails<D>::TextReplyMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails)->get_TextReplyMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedReason consume_Windows_ApplicationModel_Calls_Background_IPhoneIncomingCallDismissedTriggerDetails<D>::Reason() const
{
    Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_Background_IPhoneLineChangedTriggerDetails<D>::LineId() const
{
    winrt::guid result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails)->get_LineId(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Calls::Background::PhoneLineChangeKind consume_Windows_ApplicationModel_Calls_Background_IPhoneLineChangedTriggerDetails<D>::ChangeType() const
{
    Windows::ApplicationModel::Calls::Background::PhoneLineChangeKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails)->get_ChangeType(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_Background_IPhoneLineChangedTriggerDetails<D>::HasLinePropertyChanged(Windows::ApplicationModel::Calls::Background::PhoneLineProperties const& lineProperty) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails)->HasLinePropertyChanged(get_abi(lineProperty), &result));
    return result;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_Background_IPhoneNewVoicemailMessageTriggerDetails<D>::LineId() const
{
    winrt::guid result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails)->get_LineId(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Calls_Background_IPhoneNewVoicemailMessageTriggerDetails<D>::VoicemailCount() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails)->get_VoicemailCount(&result));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_Background_IPhoneNewVoicemailMessageTriggerDetails<D>::OperatorMessage() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails)->get_OperatorMessage(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails> : produce_base<D, Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails>
{
    int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LineId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CallBlockedReason(Windows::ApplicationModel::Calls::Background::PhoneCallBlockedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallBlockedReason, WINRT_WRAP(Windows::ApplicationModel::Calls::Background::PhoneCallBlockedReason));
            *value = detach_from<Windows::ApplicationModel::Calls::Background::PhoneCallBlockedReason>(this->shim().CallBlockedReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails> : produce_base<D, Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails>
{
    int32_t WINRT_CALL get_RequestId(winrt::guid* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(winrt::guid));
            *result = detach_from<winrt::guid>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneNumber(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails> : produce_base<D, Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails>
{
    int32_t WINRT_CALL get_LineId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LineId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DismissalTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DismissalTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DismissalTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextReplyMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextReplyMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TextReplyMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedReason));
            *value = detach_from<Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails> : produce_base<D, Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails>
{
    int32_t WINRT_CALL get_LineId(winrt::guid* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineId, WINRT_WRAP(winrt::guid));
            *result = detach_from<winrt::guid>(this->shim().LineId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangeType(Windows::ApplicationModel::Calls::Background::PhoneLineChangeKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeType, WINRT_WRAP(Windows::ApplicationModel::Calls::Background::PhoneLineChangeKind));
            *result = detach_from<Windows::ApplicationModel::Calls::Background::PhoneLineChangeKind>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HasLinePropertyChanged(Windows::ApplicationModel::Calls::Background::PhoneLineProperties lineProperty, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasLinePropertyChanged, WINRT_WRAP(bool), Windows::ApplicationModel::Calls::Background::PhoneLineProperties const&);
            *result = detach_from<bool>(this->shim().HasLinePropertyChanged(*reinterpret_cast<Windows::ApplicationModel::Calls::Background::PhoneLineProperties const*>(&lineProperty)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails> : produce_base<D, Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails>
{
    int32_t WINRT_CALL get_LineId(winrt::guid* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineId, WINRT_WRAP(winrt::guid));
            *result = detach_from<winrt::guid>(this->shim().LineId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VoicemailCount(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VoicemailCount, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().VoicemailCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OperatorMessage(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperatorMessage, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().OperatorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Background {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::PhoneCallBlockedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::PhoneCallBlockedTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::PhoneCallOriginDataRequestTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::PhoneCallOriginDataRequestTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::PhoneIncomingCallDismissedTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::PhoneLineChangedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::PhoneLineChangedTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::Background::PhoneNewVoicemailMessageTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::Background::PhoneNewVoicemailMessageTriggerDetails> {};

}
