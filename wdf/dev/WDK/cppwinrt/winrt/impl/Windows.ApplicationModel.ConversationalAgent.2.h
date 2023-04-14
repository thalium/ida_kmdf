// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Media.Audio.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.ConversationalAgent.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ConversationalAgent {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ConversationalAgent {

struct WINRT_EBO ConversationalAgentSession :
    Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession,
    impl::require<ConversationalAgentSession, Windows::Foundation::IClosable>
{
    ConversationalAgentSession(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> GetCurrentSessionAsync();
    static Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession GetCurrentSessionSync();
};

struct WINRT_EBO ConversationalAgentSessionInterruptedEventArgs :
    Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs
{
    ConversationalAgentSessionInterruptedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ConversationalAgentSignal :
    Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal
{
    ConversationalAgentSignal(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ConversationalAgentSignalDetectedEventArgs :
    Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs
{
    ConversationalAgentSignalDetectedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ConversationalAgentSystemStateChangedEventArgs :
    Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs
{
    ConversationalAgentSystemStateChangedEventArgs(std::nullptr_t) noexcept {}
};

}
