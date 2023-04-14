// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media::Audio {

struct AudioDeviceInputNode;
struct AudioGraph;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ConversationalAgent {

enum class ConversationalAgentSessionUpdateResponse : int32_t
{
    Success = 0,
    Failed = 1,
};

enum class ConversationalAgentState : int32_t
{
    Inactive = 0,
    Detecting = 1,
    Listening = 2,
    Working = 3,
    Speaking = 4,
    ListeningAndSpeaking = 5,
};

enum class ConversationalAgentSystemStateChangeType : int32_t
{
    UserAuthentication = 0,
    ScreenAvailability = 1,
    IndicatorLightAvailability = 2,
    VoiceActivationAvailability = 3,
};

struct IConversationalAgentSession;
struct IConversationalAgentSessionInterruptedEventArgs;
struct IConversationalAgentSessionStatics;
struct IConversationalAgentSignal;
struct IConversationalAgentSignalDetectedEventArgs;
struct IConversationalAgentSystemStateChangedEventArgs;
struct ConversationalAgentSession;
struct ConversationalAgentSessionInterruptedEventArgs;
struct ConversationalAgentSignal;
struct ConversationalAgentSignalDetectedEventArgs;
struct ConversationalAgentSystemStateChangedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionUpdateResponse" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentState" }; };
template <> struct name<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType>{ static constexpr auto & value{ L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangeType" }; };
template <> struct guid_storage<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>{ static constexpr guid value{ 0xDAAAE09A,0xB7BA,0x57E5,{ 0xAD,0x13,0xDF,0x52,0x0F,0x9B,0x6F,0xA7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs>{ static constexpr guid value{ 0x9766591F,0xF63D,0x5D3E,{ 0x9B,0xF2,0xBD,0x07,0x60,0x55,0x26,0x86 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>{ static constexpr guid value{ 0xA005166E,0xE954,0x576E,{ 0xBE,0x04,0x11,0xB8,0xED,0x10,0xF3,0x7B } }; };
template <> struct guid_storage<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal>{ static constexpr guid value{ 0x20ED25F7,0xB120,0x51F2,{ 0x86,0x03,0x26,0x5D,0x6A,0x47,0xF2,0x32 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs>{ static constexpr guid value{ 0x4D57EB8F,0xF88A,0x599B,{ 0x91,0xD3,0xD6,0x04,0x87,0x67,0x08,0xBC } }; };
template <> struct guid_storage<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs>{ static constexpr guid value{ 0x1C2C6E3E,0x2785,0x59A7,{ 0x8E,0x71,0x38,0xAD,0xEE,0xF7,0x99,0x28 } }; };
template <> struct default_interface<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession>{ using type = Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession; };
template <> struct default_interface<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs>{ using type = Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal>{ using type = Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal; };
template <> struct default_interface<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs>{ using type = Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs>{ using type = Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs; };

template <> struct abi<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SessionInterrupted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SessionInterrupted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SignalDetected(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SignalDetected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SystemStateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SystemStateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_AgentState(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Signal(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsIndicatorLightAvailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsScreenAvailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsUserAuthenticated(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVoiceActivationAvailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInterruptible(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInterrupted(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestInterruptibleAsync(bool interruptible, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestInterruptible(bool interruptible, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse* result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAgentStateChangeAsync(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState state, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAgentStateChange(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState state, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse* result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestForegroundActivationAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestForegroundActivation(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioClientAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioClient(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAudioDeviceInputNodeAsync(void* graph, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAudioDeviceInputNode(void* graph, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioCaptureDeviceIdAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioCaptureDeviceId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioRenderDeviceIdAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioRenderDeviceId(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSignalModelIdAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSignalModelId(uint32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetSignalModelIdAsync(uint32_t signalModelId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetSignalModelId(uint32_t signalModelId, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSupportedSignalModelIdsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetSupportedSignalModelIds(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCurrentSessionAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentSessionSync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSignalVerificationRequired(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsSignalVerificationRequired(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SignalId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SignalName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalContext(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SignalContext(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalStart(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SignalStart(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalEnd(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SignalEnd(Windows::Foundation::TimeSpan value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SystemStateChangeType(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession
{
    winrt::event_token SessionInterrupted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> const& handler) const;
    using SessionInterrupted_revoker = impl::event_revoker<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession, &impl::abi_t<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>::remove_SessionInterrupted>;
    SessionInterrupted_revoker SessionInterrupted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs> const& handler) const;
    void SessionInterrupted(winrt::event_token const& token) const noexcept;
    winrt::event_token SignalDetected(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> const& handler) const;
    using SignalDetected_revoker = impl::event_revoker<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession, &impl::abi_t<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>::remove_SignalDetected>;
    SignalDetected_revoker SignalDetected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs> const& handler) const;
    void SignalDetected(winrt::event_token const& token) const noexcept;
    winrt::event_token SystemStateChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> const& handler) const;
    using SystemStateChanged_revoker = impl::event_revoker<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession, &impl::abi_t<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession>::remove_SystemStateChanged>;
    SystemStateChanged_revoker SystemStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession, Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs> const& handler) const;
    void SystemStateChanged(winrt::event_token const& token) const noexcept;
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState AgentState() const;
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignal Signal() const;
    bool IsIndicatorLightAvailable() const;
    bool IsScreenAvailable() const;
    bool IsUserAuthenticated() const;
    bool IsVoiceActivationAvailable() const;
    bool IsInterruptible() const;
    bool IsInterrupted() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> RequestInterruptibleAsync(bool interruptible) const;
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse RequestInterruptible(bool interruptible) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> RequestAgentStateChangeAsync(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const& state) const;
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse RequestAgentStateChange(Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState const& state) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> RequestForegroundActivationAsync() const;
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse RequestForegroundActivation() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> GetAudioClientAsync() const;
    Windows::Foundation::IInspectable GetAudioClient() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::AudioDeviceInputNode> CreateAudioDeviceInputNodeAsync(Windows::Media::Audio::AudioGraph const& graph) const;
    Windows::Media::Audio::AudioDeviceInputNode CreateAudioDeviceInputNode(Windows::Media::Audio::AudioGraph const& graph) const;
    Windows::Foundation::IAsyncOperation<hstring> GetAudioCaptureDeviceIdAsync() const;
    hstring GetAudioCaptureDeviceId() const;
    Windows::Foundation::IAsyncOperation<hstring> GetAudioRenderDeviceIdAsync() const;
    hstring GetAudioRenderDeviceId() const;
    Windows::Foundation::IAsyncOperation<uint32_t> GetSignalModelIdAsync() const;
    uint32_t GetSignalModelId() const;
    Windows::Foundation::IAsyncOperation<bool> SetSignalModelIdAsync(uint32_t signalModelId) const;
    bool SetSignalModelId(uint32_t signalModelId) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<uint32_t>> GetSupportedSignalModelIdsAsync() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> GetSupportedSignalModelIds() const;
};
template <> struct consume<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession> { template <typename D> using type = consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionInterruptedEventArgs
{
};
template <> struct consume<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionInterruptedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionStatics
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession> GetCurrentSessionAsync() const;
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession GetCurrentSessionSync() const;
};
template <> struct consume<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics> { template <typename D> using type = consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal
{
    bool IsSignalVerificationRequired() const;
    void IsSignalVerificationRequired(bool value) const;
    hstring SignalId() const;
    void SignalId(param::hstring const& value) const;
    hstring SignalName() const;
    void SignalName(param::hstring const& value) const;
    Windows::Foundation::IInspectable SignalContext() const;
    void SignalContext(Windows::Foundation::IInspectable const& value) const;
    Windows::Foundation::TimeSpan SignalStart() const;
    void SignalStart(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan SignalEnd() const;
    void SignalEnd(Windows::Foundation::TimeSpan const& value) const;
};
template <> struct consume<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal> { template <typename D> using type = consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignalDetectedEventArgs
{
};
template <> struct consume<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignalDetectedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSystemStateChangedEventArgs
{
    Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType SystemStateChangeType() const;
};
template <> struct consume<Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSystemStateChangedEventArgs<D>; };

}
