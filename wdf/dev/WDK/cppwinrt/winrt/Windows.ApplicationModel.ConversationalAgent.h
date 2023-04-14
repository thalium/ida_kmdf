// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.Audio.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.ConversationalAgent.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SessionInterrupted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->add_SessionInterrupted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SessionInterrupted_revoker consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SessionInterrupted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SessionInterrupted_revoker>(this, SessionInterrupted(handler));
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SessionInterrupted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->remove_SessionInterrupted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SignalDetected(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->add_SignalDetected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SignalDetected_revoker consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SignalDetected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SignalDetected_revoker>(this, SignalDetected(handler));
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SignalDetected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->remove_SignalDetected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SystemStateChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->add_SystemStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SystemStateChanged_revoker consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SystemStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SystemStateChanged_revoker>(this, SystemStateChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SystemStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->remove_SystemStateChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::AgentState() const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_AgentState(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::Signal() const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_Signal(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::IsIndicatorLightAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_IsIndicatorLightAvailable(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::IsScreenAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_IsScreenAvailable(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::IsUserAuthenticated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_IsUserAuthenticated(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::IsVoiceActivationAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_IsVoiceActivationAvailable(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::IsInterruptible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_IsInterruptible(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::IsInterrupted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->get_IsInterrupted(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::RequestInterruptibleAsync(bool interruptible) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->RequestInterruptibleAsync(interruptible, put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::RequestInterruptible(bool interruptible) const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->RequestInterruptible(interruptible, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::RequestAgentStateChangeAsync(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const& state) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->RequestAgentStateChangeAsync(get_abi(state), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::RequestAgentStateChange(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const& state) const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->RequestAgentStateChange(get_abi(state), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::RequestForegroundActivationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->RequestForegroundActivationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::RequestForegroundActivation() const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->RequestForegroundActivation(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetAudioClientAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetAudioClientAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetAudioClient() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetAudioClient(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Audio::AudioDeviceInputNode> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::CreateAudioDeviceInputNodeAsync(Windows::Media::Audio::AudioGraph const& graph) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::AudioDeviceInputNode> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->CreateAudioDeviceInputNodeAsync(get_abi(graph), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Audio::AudioDeviceInputNode consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::CreateAudioDeviceInputNode(Windows::Media::Audio::AudioGraph const& graph) const
{
    Windows::Media::Audio::AudioDeviceInputNode result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->CreateAudioDeviceInputNode(get_abi(graph), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetAudioCaptureDeviceIdAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetAudioCaptureDeviceIdAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetAudioCaptureDeviceId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetAudioCaptureDeviceId(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetAudioRenderDeviceIdAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetAudioRenderDeviceIdAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetAudioRenderDeviceId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetAudioRenderDeviceId(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetSignalModelIdAsync() const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetSignalModelIdAsync(put_abi(operation)));
    return operation;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetSignalModelId() const
{
    uint32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetSignalModelId(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SetSignalModelIdAsync(uint32_t signalModelId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->SetSignalModelIdAsync(signalModelId, put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::SetSignalModelId(uint32_t signalModelId) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->SetSignalModelId(signalModelId, &result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetSupportedSignalModelIdsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetSupportedSignalModelIdsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>::GetSupportedSignalModelIds() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession)->GetSupportedSignalModelIds(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionStatics<D>::GetCurrentSessionAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics)->GetCurrentSessionAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionStatics<D>::GetCurrentSessionSync() const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics)->GetCurrentSessionSync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::IsSignalVerificationRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->get_IsSignalVerificationRequired(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::IsSignalVerificationRequired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->put_IsSignalVerificationRequired(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->get_SignalId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->put_SignalId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->get_SignalName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->put_SignalName(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalContext() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->get_SignalContext(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalContext(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->put_SignalContext(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalStart() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->get_SignalStart(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalStart(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->put_SignalStart(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalEnd() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->get_SignalEnd(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>::SignalEnd(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal)->put_SignalEnd(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSystemStateChangedEventArgs<D>::SystemStateChangeType() const
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs)->get_SystemStateChangeType(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession> : produce_base<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>
{
    int32_t WINRT_CALL add_SessionInterrupted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInterrupted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionInterrupted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SessionInterrupted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SessionInterrupted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SessionInterrupted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SignalDetected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalDetected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SignalDetected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SignalDetected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SignalDetected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SignalDetected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SystemStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SystemStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SystemStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SystemStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SystemStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_AgentState(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AgentState, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState));
            *value = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState>(this->shim().AgentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Signal(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Signal, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal));
            *value = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal>(this->shim().Signal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIndicatorLightAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIndicatorLightAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIndicatorLightAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsScreenAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScreenAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsScreenAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUserAuthenticated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUserAuthenticated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUserAuthenticated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVoiceActivationAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVoiceActivationAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVoiceActivationAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInterruptible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterruptible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInterruptible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInterrupted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterrupted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInterrupted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestInterruptibleAsync(bool interruptible, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestInterruptibleAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>), bool);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>>(this->shim().RequestInterruptibleAsync(interruptible));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestInterruptible(bool interruptible, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestInterruptible, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse), bool);
            *result = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>(this->shim().RequestInterruptible(interruptible));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAgentStateChangeAsync(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState state, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAgentStateChangeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>), Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>>(this->shim().RequestAgentStateChangeAsync(*reinterpret_cast<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAgentStateChange(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState state, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAgentStateChange, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse), Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const&);
            *result = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>(this->shim().RequestAgentStateChange(*reinterpret_cast<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestForegroundActivationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestForegroundActivationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>>(this->shim().RequestForegroundActivationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestForegroundActivation(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestForegroundActivation, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse));
            *result = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>(this->shim().RequestForegroundActivation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioClientAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioClientAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable>>(this->shim().GetAudioClientAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioClient(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioClient, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetAudioClient());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAudioDeviceInputNodeAsync(void* graph, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAudioDeviceInputNodeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Audio::AudioDeviceInputNode>), Windows::Media::Audio::AudioGraph const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Audio::AudioDeviceInputNode>>(this->shim().CreateAudioDeviceInputNodeAsync(*reinterpret_cast<Windows::Media::Audio::AudioGraph const*>(&graph)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAudioDeviceInputNode(void* graph, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAudioDeviceInputNode, WINRT_WRAP(Windows::Media::Audio::AudioDeviceInputNode), Windows::Media::Audio::AudioGraph const&);
            *result = detach_from<Windows::Media::Audio::AudioDeviceInputNode>(this->shim().CreateAudioDeviceInputNode(*reinterpret_cast<Windows::Media::Audio::AudioGraph const*>(&graph)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioCaptureDeviceIdAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioCaptureDeviceIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAudioCaptureDeviceIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioCaptureDeviceId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioCaptureDeviceId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAudioCaptureDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioRenderDeviceIdAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioRenderDeviceIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetAudioRenderDeviceIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioRenderDeviceId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioRenderDeviceId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAudioRenderDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSignalModelIdAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSignalModelIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().GetSignalModelIdAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSignalModelId(uint32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSignalModelId, WINRT_WRAP(uint32_t));
            *result = detach_from<uint32_t>(this->shim().GetSignalModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSignalModelIdAsync(uint32_t signalModelId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSignalModelIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SetSignalModelIdAsync(signalModelId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSignalModelId(uint32_t signalModelId, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSignalModelId, WINRT_WRAP(bool), uint32_t);
            *result = detach_from<bool>(this->shim().SetSignalModelId(signalModelId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedSignalModelIdsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedSignalModelIdsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>>>(this->shim().GetSupportedSignalModelIdsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSupportedSignalModelIds(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSupportedSignalModelIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().GetSupportedSignalModelIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs> : produce_base<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs>
{};

template <typename D>
struct produce<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics> : produce_base<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>
{
    int32_t WINRT_CALL GetCurrentSessionAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSessionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession>>(this->shim().GetCurrentSessionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentSessionSync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSessionSync, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession));
            *result = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession>(this->shim().GetCurrentSessionSync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal> : produce_base<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal>
{
    int32_t WINRT_CALL get_IsSignalVerificationRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSignalVerificationRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSignalVerificationRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSignalVerificationRequired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSignalVerificationRequired, WINRT_WRAP(void), bool);
            this->shim().IsSignalVerificationRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SignalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignalId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalId, WINRT_WRAP(void), hstring const&);
            this->shim().SignalId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SignalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignalName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalName, WINRT_WRAP(void), hstring const&);
            this->shim().SignalName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalContext, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().SignalContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignalContext(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalContext, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().SignalContext(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalStart(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalStart, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SignalStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignalStart(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalStart, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().SignalStart(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalEnd(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalEnd, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SignalEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignalEnd(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalEnd, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().SignalEnd(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs> : produce_base<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs>
{};

template <typename D>
struct produce<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs> : produce_base<D, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs>
{
    int32_t WINRT_CALL get_SystemStateChangeType(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemStateChangeType, WINRT_WRAP(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType));
            *value = detach_from<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType>(this->shim().SystemStateChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ConversationalAgent {

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> ConversationalAgentSession::GetCurrentSessionAsync()
{
    return impl::call_factory<ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>([&](auto&& f) { return f.GetCurrentSessionAsync(); });
}

inline Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession ConversationalAgentSession::GetCurrentSessionSync()
{
    return impl::call_factory<ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>([&](auto&& f) { return f.GetCurrentSessionSync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> {};

}
