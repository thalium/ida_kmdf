// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.Sms.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Sms {

struct SmsDeviceStatusChangedEventHandler : Windows::Foundation::IUnknown
{
    SmsDeviceStatusChangedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> SmsDeviceStatusChangedEventHandler(L lambda);
    template <typename F> SmsDeviceStatusChangedEventHandler(F* function);
    template <typename O, typename M> SmsDeviceStatusChangedEventHandler(O* object, M method);
    template <typename O, typename M> SmsDeviceStatusChangedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> SmsDeviceStatusChangedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Devices::Sms::SmsDevice const& sender) const;
};

struct SmsMessageReceivedEventHandler : Windows::Foundation::IUnknown
{
    SmsMessageReceivedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> SmsMessageReceivedEventHandler(L lambda);
    template <typename F> SmsMessageReceivedEventHandler(F* function);
    template <typename O, typename M> SmsMessageReceivedEventHandler(O* object, M method);
    template <typename O, typename M> SmsMessageReceivedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> SmsMessageReceivedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Devices::Sms::SmsDevice const& sender, Windows::Devices::Sms::SmsMessageReceivedEventArgs const& e) const;
};

struct SmsEncodedLength
{
    uint32_t SegmentCount;
    uint32_t CharacterCountLastSegment;
    uint32_t CharactersPerSegment;
    uint32_t ByteCountLastSegment;
    uint32_t BytesPerSegment;
};

inline bool operator==(SmsEncodedLength const& left, SmsEncodedLength const& right) noexcept
{
    return left.SegmentCount == right.SegmentCount && left.CharacterCountLastSegment == right.CharacterCountLastSegment && left.CharactersPerSegment == right.CharactersPerSegment && left.ByteCountLastSegment == right.ByteCountLastSegment && left.BytesPerSegment == right.BytesPerSegment;
}

inline bool operator!=(SmsEncodedLength const& left, SmsEncodedLength const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Sms {

struct WINRT_EBO DeleteSmsMessageOperation :
    Windows::Foundation::IAsyncAction
{
    DeleteSmsMessageOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DeleteSmsMessagesOperation :
    Windows::Foundation::IAsyncAction
{
    DeleteSmsMessagesOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GetSmsDeviceOperation :
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>
{
    GetSmsDeviceOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GetSmsMessageOperation :
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::ISmsMessage>
{
    GetSmsMessageOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GetSmsMessagesOperation :
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsMessage>, int32_t>
{
    GetSmsMessagesOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SendSmsMessageOperation :
    Windows::Foundation::IAsyncAction
{
    SendSmsMessageOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsAppMessage :
    Windows::Devices::Sms::ISmsAppMessage
{
    SmsAppMessage(std::nullptr_t) noexcept {}
    SmsAppMessage();
};

struct WINRT_EBO SmsBinaryMessage :
    Windows::Devices::Sms::ISmsBinaryMessage
{
    SmsBinaryMessage(std::nullptr_t) noexcept {}
    SmsBinaryMessage();
};

struct WINRT_EBO SmsBroadcastMessage :
    Windows::Devices::Sms::ISmsBroadcastMessage
{
    SmsBroadcastMessage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsDevice :
    Windows::Devices::Sms::ISmsDevice
{
    SmsDevice(std::nullptr_t) noexcept {}
    static hstring GetDeviceSelector();
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> FromIdAsync(param::hstring const& deviceId);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> GetDefaultAsync();
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> FromNetworkAccountIdAsync(param::hstring const& networkAccountId);
};

struct WINRT_EBO SmsDevice2 :
    Windows::Devices::Sms::ISmsDevice2
{
    SmsDevice2(std::nullptr_t) noexcept {}
    static hstring GetDeviceSelector();
    static Windows::Devices::Sms::SmsDevice2 FromId(param::hstring const& deviceId);
    static Windows::Devices::Sms::SmsDevice2 GetDefault();
    static Windows::Devices::Sms::SmsDevice2 FromParentId(param::hstring const& parentDeviceId);
};

struct WINRT_EBO SmsDeviceMessageStore :
    Windows::Devices::Sms::ISmsDeviceMessageStore
{
    SmsDeviceMessageStore(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsFilterRule :
    Windows::Devices::Sms::ISmsFilterRule
{
    SmsFilterRule(std::nullptr_t) noexcept {}
    SmsFilterRule(Windows::Devices::Sms::SmsMessageType const& messageType);
};

struct WINRT_EBO SmsFilterRules :
    Windows::Devices::Sms::ISmsFilterRules
{
    SmsFilterRules(std::nullptr_t) noexcept {}
    SmsFilterRules(Windows::Devices::Sms::SmsFilterActionType const& actionType);
};

struct WINRT_EBO SmsMessageReceivedEventArgs :
    Windows::Devices::Sms::ISmsMessageReceivedEventArgs
{
    SmsMessageReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsMessageReceivedTriggerDetails :
    Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails
{
    SmsMessageReceivedTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsMessageRegistration :
    Windows::Devices::Sms::ISmsMessageRegistration
{
    SmsMessageRegistration(std::nullptr_t) noexcept {}
    static Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::SmsMessageRegistration> AllRegistrations();
    static Windows::Devices::Sms::SmsMessageRegistration Register(param::hstring const& id, Windows::Devices::Sms::SmsFilterRules const& filterRules);
};

struct WINRT_EBO SmsReceivedEventDetails :
    Windows::Devices::Sms::ISmsReceivedEventDetails,
    impl::require<SmsReceivedEventDetails, Windows::Devices::Sms::ISmsReceivedEventDetails2>
{
    SmsReceivedEventDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsSendMessageResult :
    Windows::Devices::Sms::ISmsSendMessageResult
{
    SmsSendMessageResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsStatusMessage :
    Windows::Devices::Sms::ISmsStatusMessage
{
    SmsStatusMessage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsTextMessage :
    Windows::Devices::Sms::ISmsTextMessage
{
    SmsTextMessage(std::nullptr_t) noexcept {}
    SmsTextMessage();
    static Windows::Devices::Sms::SmsTextMessage FromBinaryMessage(Windows::Devices::Sms::SmsBinaryMessage const& binaryMessage);
    static Windows::Devices::Sms::SmsTextMessage FromBinaryData(Windows::Devices::Sms::SmsDataFormat const& format, array_view<uint8_t const> value);
};

struct WINRT_EBO SmsTextMessage2 :
    Windows::Devices::Sms::ISmsTextMessage2
{
    SmsTextMessage2(std::nullptr_t) noexcept {}
    SmsTextMessage2();
};

struct WINRT_EBO SmsVoicemailMessage :
    Windows::Devices::Sms::ISmsVoicemailMessage
{
    SmsVoicemailMessage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SmsWapMessage :
    Windows::Devices::Sms::ISmsWapMessage
{
    SmsWapMessage(std::nullptr_t) noexcept {}
};

}
