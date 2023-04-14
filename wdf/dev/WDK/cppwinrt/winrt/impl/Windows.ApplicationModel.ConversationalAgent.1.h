// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Media.Audio.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.ApplicationModel.ConversationalAgent.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ConversationalAgent {

struct WINRT_EBO IConversationalAgentSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IConversationalAgentSession>
{
    IConversationalAgentSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IConversationalAgentSessionInterruptedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IConversationalAgentSessionInterruptedEventArgs>
{
    IConversationalAgentSessionInterruptedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IConversationalAgentSessionStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IConversationalAgentSessionStatics>
{
    IConversationalAgentSessionStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IConversationalAgentSignal :
    Windows::Foundation::IInspectable,
    impl::consume_t<IConversationalAgentSignal>
{
    IConversationalAgentSignal(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IConversationalAgentSignalDetectedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IConversationalAgentSignalDetectedEventArgs>
{
    IConversationalAgentSignalDetectedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IConversationalAgentSystemStateChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IConversationalAgentSystemStateChangedEventArgs>
{
    IConversationalAgentSystemStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
