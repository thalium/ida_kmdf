// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Calls.Background.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Background {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Background {

struct WINRT_EBO PhoneCallBlockedTriggerDetails :
    Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails
{
    PhoneCallBlockedTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PhoneCallOriginDataRequestTriggerDetails :
    Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails
{
    PhoneCallOriginDataRequestTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PhoneIncomingCallDismissedTriggerDetails :
    Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails
{
    PhoneIncomingCallDismissedTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PhoneLineChangedTriggerDetails :
    Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails
{
    PhoneLineChangedTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PhoneNewVoicemailMessageTriggerDetails :
    Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails
{
    PhoneNewVoicemailMessageTriggerDetails(std::nullptr_t) noexcept {}
};

}
