// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Sms.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsAppMessage<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsAppMessage<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::To(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_To(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsAppMessage<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_From(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsAppMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::Body(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_Body(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsAppMessage<D>::CallbackNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_CallbackNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::CallbackNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_CallbackNumber(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_Sms_ISmsAppMessage<D>::IsDeliveryNotificationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_IsDeliveryNotificationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::IsDeliveryNotificationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_IsDeliveryNotificationEnabled(value));
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsAppMessage<D>::RetryAttemptCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_RetryAttemptCount(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::RetryAttemptCount(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_RetryAttemptCount(value));
}

template <typename D> Windows::Devices::Sms::SmsEncoding consume_Windows_Devices_Sms_ISmsAppMessage<D>::Encoding() const
{
    Windows::Devices::Sms::SmsEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_Encoding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::Encoding(Windows::Devices::Sms::SmsEncoding const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_Encoding(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsAppMessage<D>::PortNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_PortNumber(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::PortNumber(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_PortNumber(value));
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsAppMessage<D>::TeleserviceId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_TeleserviceId(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::TeleserviceId(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_TeleserviceId(value));
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsAppMessage<D>::ProtocolId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_ProtocolId(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::ProtocolId(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_ProtocolId(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Sms_ISmsAppMessage<D>::BinaryBody() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->get_BinaryBody(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsAppMessage<D>::BinaryBody(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsAppMessage)->put_BinaryBody(get_abi(value)));
}

template <typename D> Windows::Devices::Sms::SmsDataFormat consume_Windows_Devices_Sms_ISmsBinaryMessage<D>::Format() const
{
    Windows::Devices::Sms::SmsDataFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBinaryMessage)->get_Format(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsBinaryMessage<D>::Format(Windows::Devices::Sms::SmsDataFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBinaryMessage)->put_Format(get_abi(value)));
}

template <typename D> com_array<uint8_t> consume_Windows_Devices_Sms_ISmsBinaryMessage<D>::GetData() const
{
    com_array<uint8_t> value;
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBinaryMessage)->GetData(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsBinaryMessage<D>::SetData(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBinaryMessage)->SetData(value.size(), get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::Channel() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_Channel(&value));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsGeographicalScope consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::GeographicalScope() const
{
    Windows::Devices::Sms::SmsGeographicalScope value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_GeographicalScope(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::MessageCode() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_MessageCode(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::UpdateNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_UpdateNumber(&value));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsBroadcastType consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::BroadcastType() const
{
    Windows::Devices::Sms::SmsBroadcastType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_BroadcastType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::IsEmergencyAlert() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_IsEmergencyAlert(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Sms_ISmsBroadcastMessage<D>::IsUserPopupRequested() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsBroadcastMessage)->get_IsUserPopupRequested(&value));
    return value;
}

template <typename D> Windows::Devices::Sms::SendSmsMessageOperation consume_Windows_Devices_Sms_ISmsDevice<D>::SendMessageAsync(Windows::Devices::Sms::ISmsMessage const& message) const
{
    Windows::Devices::Sms::SendSmsMessageOperation asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->SendMessageAsync(get_abi(message), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Devices::Sms::SmsEncodedLength consume_Windows_Devices_Sms_ISmsDevice<D>::CalculateLength(Windows::Devices::Sms::SmsTextMessage const& message) const
{
    Windows::Devices::Sms::SmsEncodedLength encodedLength{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->CalculateLength(get_abi(message), put_abi(encodedLength)));
    return encodedLength;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDevice<D>::AccountPhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->get_AccountPhoneNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::CellularClass consume_Windows_Devices_Sms_ISmsDevice<D>::CellularClass() const
{
    Windows::Devices::Sms::CellularClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->get_CellularClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsDeviceMessageStore consume_Windows_Devices_Sms_ISmsDevice<D>::MessageStore() const
{
    Windows::Devices::Sms::SmsDeviceMessageStore value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->get_MessageStore(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsDeviceStatus consume_Windows_Devices_Sms_ISmsDevice<D>::DeviceStatus() const
{
    Windows::Devices::Sms::SmsDeviceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->get_DeviceStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sms_ISmsDevice<D>::SmsMessageReceived(Windows::Devices::Sms::SmsMessageReceivedEventHandler const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->add_SmsMessageReceived(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Sms_ISmsDevice<D>::SmsMessageReceived_revoker consume_Windows_Devices_Sms_ISmsDevice<D>::SmsMessageReceived(auto_revoke_t, Windows::Devices::Sms::SmsMessageReceivedEventHandler const& eventHandler) const
{
    return impl::make_event_revoker<D, SmsMessageReceived_revoker>(this, SmsMessageReceived(eventHandler));
}

template <typename D> void consume_Windows_Devices_Sms_ISmsDevice<D>::SmsMessageReceived(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->remove_SmsMessageReceived(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Sms_ISmsDevice<D>::SmsDeviceStatusChanged(Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->add_SmsDeviceStatusChanged(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Sms_ISmsDevice<D>::SmsDeviceStatusChanged_revoker consume_Windows_Devices_Sms_ISmsDevice<D>::SmsDeviceStatusChanged(auto_revoke_t, Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler const& eventHandler) const
{
    return impl::make_event_revoker<D, SmsDeviceStatusChanged_revoker>(this, SmsDeviceStatusChanged(eventHandler));
}

template <typename D> void consume_Windows_Devices_Sms_ISmsDevice<D>::SmsDeviceStatusChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sms::ISmsDevice)->remove_SmsDeviceStatusChanged(get_abi(eventCookie)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDevice2<D>::SmscAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->get_SmscAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsDevice2<D>::SmscAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->put_SmscAddress(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDevice2<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDevice2<D>::ParentDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->get_ParentDeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDevice2<D>::AccountPhoneNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->get_AccountPhoneNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::CellularClass consume_Windows_Devices_Sms_ISmsDevice2<D>::CellularClass() const
{
    Windows::Devices::Sms::CellularClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->get_CellularClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsDeviceStatus consume_Windows_Devices_Sms_ISmsDevice2<D>::DeviceStatus() const
{
    Windows::Devices::Sms::SmsDeviceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->get_DeviceStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsEncodedLength consume_Windows_Devices_Sms_ISmsDevice2<D>::CalculateLength(Windows::Devices::Sms::ISmsMessageBase const& message) const
{
    Windows::Devices::Sms::SmsEncodedLength value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->CalculateLength(get_abi(message), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsSendMessageResult> consume_Windows_Devices_Sms_ISmsDevice2<D>::SendMessageAndGetResultAsync(Windows::Devices::Sms::ISmsMessageBase const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsSendMessageResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->SendMessageAndGetResultAsync(get_abi(message), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sms_ISmsDevice2<D>::DeviceStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsDevice2, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->add_DeviceStatusChanged(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Sms_ISmsDevice2<D>::DeviceStatusChanged_revoker consume_Windows_Devices_Sms_ISmsDevice2<D>::DeviceStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsDevice2, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, DeviceStatusChanged_revoker>(this, DeviceStatusChanged(eventHandler));
}

template <typename D> void consume_Windows_Devices_Sms_ISmsDevice2<D>::DeviceStatusChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2)->remove_DeviceStatusChanged(get_abi(eventCookie)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDevice2Statics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2Statics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsDevice2 consume_Windows_Devices_Sms_ISmsDevice2Statics<D>::FromId(param::hstring const& deviceId) const
{
    Windows::Devices::Sms::SmsDevice2 value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2Statics)->FromId(get_abi(deviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsDevice2 consume_Windows_Devices_Sms_ISmsDevice2Statics<D>::GetDefault() const
{
    Windows::Devices::Sms::SmsDevice2 value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2Statics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsDevice2 consume_Windows_Devices_Sms_ISmsDevice2Statics<D>::FromParentId(param::hstring const& parentDeviceId) const
{
    Windows::Devices::Sms::SmsDevice2 value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDevice2Statics)->FromParentId(get_abi(parentDeviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Sms_ISmsDeviceMessageStore<D>::DeleteMessageAsync(uint32_t messageId) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceMessageStore)->DeleteMessageAsync(messageId, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Sms_ISmsDeviceMessageStore<D>::DeleteMessagesAsync(Windows::Devices::Sms::SmsMessageFilter const& messageFilter) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceMessageStore)->DeleteMessagesAsync(get_abi(messageFilter), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::ISmsMessage> consume_Windows_Devices_Sms_ISmsDeviceMessageStore<D>::GetMessageAsync(uint32_t messageId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::ISmsMessage> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceMessageStore)->GetMessageAsync(messageId, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsMessage>, int32_t> consume_Windows_Devices_Sms_ISmsDeviceMessageStore<D>::GetMessagesAsync(Windows::Devices::Sms::SmsMessageFilter const& messageFilter) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsMessage>, int32_t> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceMessageStore)->GetMessagesAsync(get_abi(messageFilter), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> uint32_t consume_Windows_Devices_Sms_ISmsDeviceMessageStore<D>::MaxMessages() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceMessageStore)->get_MaxMessages(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsDeviceStatics<D>::GetDeviceSelector() const
{
    hstring phstrDeviceClassSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceStatics)->GetDeviceSelector(put_abi(phstrDeviceClassSelector)));
    return phstrDeviceClassSelector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> consume_Windows_Devices_Sms_ISmsDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceStatics)->FromIdAsync(get_abi(deviceId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> consume_Windows_Devices_Sms_ISmsDeviceStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceStatics)->GetDefaultAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> consume_Windows_Devices_Sms_ISmsDeviceStatics2<D>::FromNetworkAccountIdAsync(param::hstring const& networkAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsDeviceStatics2)->FromNetworkAccountIdAsync(get_abi(networkAccountId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Devices::Sms::SmsMessageType consume_Windows_Devices_Sms_ISmsFilterRule<D>::MessageType() const
{
    Windows::Devices::Sms::SmsMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Sms_ISmsFilterRule<D>::ImsiPrefixes() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_ImsiPrefixes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Sms_ISmsFilterRule<D>::DeviceIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_DeviceIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Sms_ISmsFilterRule<D>::SenderNumbers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_SenderNumbers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Sms_ISmsFilterRule<D>::TextMessagePrefixes() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_TextMessagePrefixes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<int32_t> consume_Windows_Devices_Sms_ISmsFilterRule<D>::PortNumbers() const
{
    Windows::Foundation::Collections::IVector<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_PortNumbers(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::CellularClass consume_Windows_Devices_Sms_ISmsFilterRule<D>::CellularClass() const
{
    Windows::Devices::Sms::CellularClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_CellularClass(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsFilterRule<D>::CellularClass(Windows::Devices::Sms::CellularClass const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->put_CellularClass(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<int32_t> consume_Windows_Devices_Sms_ISmsFilterRule<D>::ProtocolIds() const
{
    Windows::Foundation::Collections::IVector<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_ProtocolIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<int32_t> consume_Windows_Devices_Sms_ISmsFilterRule<D>::TeleserviceIds() const
{
    Windows::Foundation::Collections::IVector<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_TeleserviceIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Sms_ISmsFilterRule<D>::WapApplicationIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_WapApplicationIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Sms_ISmsFilterRule<D>::WapContentTypes() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_WapContentTypes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsBroadcastType> consume_Windows_Devices_Sms_ISmsFilterRule<D>::BroadcastTypes() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsBroadcastType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_BroadcastTypes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<int32_t> consume_Windows_Devices_Sms_ISmsFilterRule<D>::BroadcastChannels() const
{
    Windows::Foundation::Collections::IVector<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRule)->get_BroadcastChannels(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsFilterRule consume_Windows_Devices_Sms_ISmsFilterRuleFactory<D>::CreateFilterRule(Windows::Devices::Sms::SmsMessageType const& messageType) const
{
    Windows::Devices::Sms::SmsFilterRule value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRuleFactory)->CreateFilterRule(get_abi(messageType), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsFilterActionType consume_Windows_Devices_Sms_ISmsFilterRules<D>::ActionType() const
{
    Windows::Devices::Sms::SmsFilterActionType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRules)->get_ActionType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsFilterRule> consume_Windows_Devices_Sms_ISmsFilterRules<D>::Rules() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsFilterRule> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRules)->get_Rules(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsFilterRules consume_Windows_Devices_Sms_ISmsFilterRulesFactory<D>::CreateFilterRules(Windows::Devices::Sms::SmsFilterActionType const& actionType) const
{
    Windows::Devices::Sms::SmsFilterRules value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsFilterRulesFactory)->CreateFilterRules(get_abi(actionType), put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sms_ISmsMessage<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessage)->get_Id(&value));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsMessageClass consume_Windows_Devices_Sms_ISmsMessage<D>::MessageClass() const
{
    Windows::Devices::Sms::SmsMessageClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessage)->get_MessageClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsMessageType consume_Windows_Devices_Sms_ISmsMessageBase<D>::MessageType() const
{
    Windows::Devices::Sms::SmsMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageBase)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsMessageBase<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageBase)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::CellularClass consume_Windows_Devices_Sms_ISmsMessageBase<D>::CellularClass() const
{
    Windows::Devices::Sms::CellularClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageBase)->get_CellularClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsMessageClass consume_Windows_Devices_Sms_ISmsMessageBase<D>::MessageClass() const
{
    Windows::Devices::Sms::SmsMessageClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageBase)->get_MessageClass(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsMessageBase<D>::SimIccId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageBase)->get_SimIccId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsTextMessage consume_Windows_Devices_Sms_ISmsMessageReceivedEventArgs<D>::TextMessage() const
{
    Windows::Devices::Sms::SmsTextMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedEventArgs)->get_TextMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsBinaryMessage consume_Windows_Devices_Sms_ISmsMessageReceivedEventArgs<D>::BinaryMessage() const
{
    Windows::Devices::Sms::SmsBinaryMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedEventArgs)->get_BinaryMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsMessageType consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::MessageType() const
{
    Windows::Devices::Sms::SmsMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsTextMessage2 consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::TextMessage() const
{
    Windows::Devices::Sms::SmsTextMessage2 value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_TextMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsWapMessage consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::WapMessage() const
{
    Windows::Devices::Sms::SmsWapMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_WapMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsAppMessage consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::AppMessage() const
{
    Windows::Devices::Sms::SmsAppMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_AppMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsBroadcastMessage consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::BroadcastMessage() const
{
    Windows::Devices::Sms::SmsBroadcastMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_BroadcastMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsVoicemailMessage consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::VoicemailMessage() const
{
    Windows::Devices::Sms::SmsVoicemailMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_VoicemailMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsStatusMessage consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::StatusMessage() const
{
    Windows::Devices::Sms::SmsStatusMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->get_StatusMessage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::Drop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->Drop());
}

template <typename D> void consume_Windows_Devices_Sms_ISmsMessageReceivedTriggerDetails<D>::Accept() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails)->Accept());
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsMessageRegistration<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageRegistration)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsMessageRegistration<D>::Unregister() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageRegistration)->Unregister());
}

template <typename D> winrt::event_token consume_Windows_Devices_Sms_ISmsMessageRegistration<D>::MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsMessageRegistration, Windows::Devices::Sms::SmsMessageReceivedTriggerDetails> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageRegistration)->add_MessageReceived(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Sms_ISmsMessageRegistration<D>::MessageReceived_revoker consume_Windows_Devices_Sms_ISmsMessageRegistration<D>::MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsMessageRegistration, Windows::Devices::Sms::SmsMessageReceivedTriggerDetails> const& eventHandler) const
{
    return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(eventHandler));
}

template <typename D> void consume_Windows_Devices_Sms_ISmsMessageRegistration<D>::MessageReceived(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sms::ISmsMessageRegistration)->remove_MessageReceived(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::SmsMessageRegistration> consume_Windows_Devices_Sms_ISmsMessageRegistrationStatics<D>::AllRegistrations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::SmsMessageRegistration> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageRegistrationStatics)->get_AllRegistrations(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsMessageRegistration consume_Windows_Devices_Sms_ISmsMessageRegistrationStatics<D>::Register(param::hstring const& id, Windows::Devices::Sms::SmsFilterRules const& filterRules) const
{
    Windows::Devices::Sms::SmsMessageRegistration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsMessageRegistrationStatics)->Register(get_abi(id), get_abi(filterRules), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsReceivedEventDetails<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsReceivedEventDetails)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sms_ISmsReceivedEventDetails<D>::MessageIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsReceivedEventDetails)->get_MessageIndex(&value));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsMessageClass consume_Windows_Devices_Sms_ISmsReceivedEventDetails2<D>::MessageClass() const
{
    Windows::Devices::Sms::SmsMessageClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsReceivedEventDetails2)->get_MessageClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsBinaryMessage consume_Windows_Devices_Sms_ISmsReceivedEventDetails2<D>::BinaryMessage() const
{
    Windows::Devices::Sms::SmsBinaryMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsReceivedEventDetails2)->get_BinaryMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::IsSuccessful() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_IsSuccessful(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int32_t> consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::MessageReferenceNumbers() const
{
    Windows::Foundation::Collections::IVectorView<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_MessageReferenceNumbers(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::CellularClass consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::CellularClass() const
{
    Windows::Devices::Sms::CellularClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_CellularClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsModemErrorCode consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::ModemErrorCode() const
{
    Windows::Devices::Sms::SmsModemErrorCode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_ModemErrorCode(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::IsErrorTransient() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_IsErrorTransient(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::NetworkCauseCode() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_NetworkCauseCode(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsSendMessageResult<D>::TransportFailureCause() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsSendMessageResult)->get_TransportFailureCause(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsStatusMessage<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsStatusMessage<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_From(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsStatusMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsStatusMessage<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_Status(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsStatusMessage<D>::MessageReferenceNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_MessageReferenceNumber(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsStatusMessage<D>::ServiceCenterTimestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_ServiceCenterTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsStatusMessage<D>::DischargeTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsStatusMessage)->get_DischargeTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsTextMessage<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sms_ISmsTextMessage<D>::PartReferenceId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_PartReferenceId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sms_ISmsTextMessage<D>::PartNumber() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_PartNumber(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sms_ISmsTextMessage<D>::PartCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_PartCount(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage<D>::To(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->put_To(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_From(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage<D>::From(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->put_From(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage<D>::Body(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->put_Body(get_abi(value)));
}

template <typename D> Windows::Devices::Sms::SmsEncoding consume_Windows_Devices_Sms_ISmsTextMessage<D>::Encoding() const
{
    Windows::Devices::Sms::SmsEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->get_Encoding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage<D>::Encoding(Windows::Devices::Sms::SmsEncoding const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->put_Encoding(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsBinaryMessage> consume_Windows_Devices_Sms_ISmsTextMessage<D>::ToBinaryMessages(Windows::Devices::Sms::SmsDataFormat const& format) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsBinaryMessage> messages{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage)->ToBinaryMessages(get_abi(format), put_abi(messages)));
    return messages;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsTextMessage2<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage2<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage2<D>::To(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->put_To(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage2<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_From(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage2<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_Body(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage2<D>::Body(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->put_Body(get_abi(value)));
}

template <typename D> Windows::Devices::Sms::SmsEncoding consume_Windows_Devices_Sms_ISmsTextMessage2<D>::Encoding() const
{
    Windows::Devices::Sms::SmsEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_Encoding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage2<D>::Encoding(Windows::Devices::Sms::SmsEncoding const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->put_Encoding(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsTextMessage2<D>::CallbackNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_CallbackNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage2<D>::CallbackNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->put_CallbackNumber(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_Sms_ISmsTextMessage2<D>::IsDeliveryNotificationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_IsDeliveryNotificationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage2<D>::IsDeliveryNotificationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->put_IsDeliveryNotificationEnabled(value));
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsTextMessage2<D>::RetryAttemptCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_RetryAttemptCount(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sms_ISmsTextMessage2<D>::RetryAttemptCount(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->put_RetryAttemptCount(value));
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsTextMessage2<D>::TeleserviceId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_TeleserviceId(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sms_ISmsTextMessage2<D>::ProtocolId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessage2)->get_ProtocolId(&value));
    return value;
}

template <typename D> Windows::Devices::Sms::SmsTextMessage consume_Windows_Devices_Sms_ISmsTextMessageStatics<D>::FromBinaryMessage(Windows::Devices::Sms::SmsBinaryMessage const& binaryMessage) const
{
    Windows::Devices::Sms::SmsTextMessage textMessage{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessageStatics)->FromBinaryMessage(get_abi(binaryMessage), put_abi(textMessage)));
    return textMessage;
}

template <typename D> Windows::Devices::Sms::SmsTextMessage consume_Windows_Devices_Sms_ISmsTextMessageStatics<D>::FromBinaryData(Windows::Devices::Sms::SmsDataFormat const& format, array_view<uint8_t const> value) const
{
    Windows::Devices::Sms::SmsTextMessage textMessage{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsTextMessageStatics)->FromBinaryData(get_abi(format), value.size(), get_abi(value), put_abi(textMessage)));
    return textMessage;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsVoicemailMessage<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsVoicemailMessage)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsVoicemailMessage<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsVoicemailMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsVoicemailMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsVoicemailMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Devices_Sms_ISmsVoicemailMessage<D>::MessageCount() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsVoicemailMessage)->get_MessageCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sms_ISmsWapMessage<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsWapMessage<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsWapMessage<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_From(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsWapMessage<D>::ApplicationId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_ApplicationId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sms_ISmsWapMessage<D>::ContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Sms_ISmsWapMessage<D>::BinaryBody() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_BinaryBody(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Devices_Sms_ISmsWapMessage<D>::Headers() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sms::ISmsWapMessage)->get_Headers(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Devices::Sms::SmsDevice const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Devices::Sms::SmsMessageReceivedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Devices::Sms::SmsMessageReceivedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Devices::Sms::SmsMessageReceivedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Devices::Sms::SmsDevice const*>(&sender), *reinterpret_cast<Windows::Devices::Sms::SmsMessageReceivedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsAppMessage> : produce_base<D, Windows::Devices::Sms::ISmsAppMessage>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), hstring const&);
            this->shim().To(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Body(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(void), hstring const&);
            this->shim().Body(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CallbackNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallbackNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CallbackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CallbackNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallbackNumber, WINRT_WRAP(void), hstring const&);
            this->shim().CallbackNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDeliveryNotificationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDeliveryNotificationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDeliveryNotificationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDeliveryNotificationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDeliveryNotificationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsDeliveryNotificationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RetryAttemptCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetryAttemptCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RetryAttemptCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RetryAttemptCount(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetryAttemptCount, WINRT_WRAP(void), int32_t);
            this->shim().RetryAttemptCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Encoding(Windows::Devices::Sms::SmsEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encoding, WINRT_WRAP(Windows::Devices::Sms::SmsEncoding));
            *value = detach_from<Windows::Devices::Sms::SmsEncoding>(this->shim().Encoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Encoding(Windows::Devices::Sms::SmsEncoding value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encoding, WINRT_WRAP(void), Windows::Devices::Sms::SmsEncoding const&);
            this->shim().Encoding(*reinterpret_cast<Windows::Devices::Sms::SmsEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PortNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PortNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PortNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PortNumber(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PortNumber, WINRT_WRAP(void), int32_t);
            this->shim().PortNumber(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TeleserviceId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TeleserviceId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TeleserviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TeleserviceId(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TeleserviceId, WINRT_WRAP(void), int32_t);
            this->shim().TeleserviceId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ProtocolId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtocolId(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolId, WINRT_WRAP(void), int32_t);
            this->shim().ProtocolId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BinaryBody(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BinaryBody, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().BinaryBody());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BinaryBody(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BinaryBody, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().BinaryBody(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsBinaryMessage> : produce_base<D, Windows::Devices::Sms::ISmsBinaryMessage>
{
    int32_t WINRT_CALL get_Format(Windows::Devices::Sms::SmsDataFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Devices::Sms::SmsDataFormat));
            *value = detach_from<Windows::Devices::Sms::SmsDataFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Format(Windows::Devices::Sms::SmsDataFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(void), Windows::Devices::Sms::SmsDataFormat const&);
            this->shim().Format(*reinterpret_cast<Windows::Devices::Sms::SmsDataFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetData(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetData, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().GetData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetData(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetData, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsBroadcastMessage> : produce_base<D, Windows::Devices::Sms::ISmsBroadcastMessage>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Channel(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Channel, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GeographicalScope(Windows::Devices::Sms::SmsGeographicalScope* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeographicalScope, WINRT_WRAP(Windows::Devices::Sms::SmsGeographicalScope));
            *value = detach_from<Windows::Devices::Sms::SmsGeographicalScope>(this->shim().GeographicalScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageCode(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageCode, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MessageCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().UpdateNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastType(Windows::Devices::Sms::SmsBroadcastType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastType, WINRT_WRAP(Windows::Devices::Sms::SmsBroadcastType));
            *value = detach_from<Windows::Devices::Sms::SmsBroadcastType>(this->shim().BroadcastType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEmergencyAlert(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEmergencyAlert, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEmergencyAlert());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUserPopupRequested(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUserPopupRequested, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUserPopupRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsDevice> : produce_base<D, Windows::Devices::Sms::ISmsDevice>
{
    int32_t WINRT_CALL SendMessageAsync(void* message, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAsync, WINRT_WRAP(Windows::Devices::Sms::SendSmsMessageOperation), Windows::Devices::Sms::ISmsMessage const);
            *asyncInfo = detach_from<Windows::Devices::Sms::SendSmsMessageOperation>(this->shim().SendMessageAsync(*reinterpret_cast<Windows::Devices::Sms::ISmsMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CalculateLength(void* message, struct struct_Windows_Devices_Sms_SmsEncodedLength* encodedLength) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalculateLength, WINRT_WRAP(Windows::Devices::Sms::SmsEncodedLength), Windows::Devices::Sms::SmsTextMessage const&);
            *encodedLength = detach_from<Windows::Devices::Sms::SmsEncodedLength>(this->shim().CalculateLength(*reinterpret_cast<Windows::Devices::Sms::SmsTextMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountPhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountPhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccountPhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(Windows::Devices::Sms::CellularClass));
            *value = detach_from<Windows::Devices::Sms::CellularClass>(this->shim().CellularClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageStore(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageStore, WINRT_WRAP(Windows::Devices::Sms::SmsDeviceMessageStore));
            *value = detach_from<Windows::Devices::Sms::SmsDeviceMessageStore>(this->shim().MessageStore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceStatus(Windows::Devices::Sms::SmsDeviceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceStatus, WINRT_WRAP(Windows::Devices::Sms::SmsDeviceStatus));
            *value = detach_from<Windows::Devices::Sms::SmsDeviceStatus>(this->shim().DeviceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SmsMessageReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmsMessageReceived, WINRT_WRAP(winrt::event_token), Windows::Devices::Sms::SmsMessageReceivedEventHandler const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().SmsMessageReceived(*reinterpret_cast<Windows::Devices::Sms::SmsMessageReceivedEventHandler const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SmsMessageReceived(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SmsMessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SmsMessageReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_SmsDeviceStatusChanged(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmsDeviceStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().SmsDeviceStatusChanged(*reinterpret_cast<Windows::Devices::Sms::SmsDeviceStatusChangedEventHandler const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SmsDeviceStatusChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SmsDeviceStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SmsDeviceStatusChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsDevice2> : produce_base<D, Windows::Devices::Sms::ISmsDevice2>
{
    int32_t WINRT_CALL get_SmscAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmscAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SmscAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmscAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmscAddress, WINRT_WRAP(void), hstring const&);
            this->shim().SmscAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParentDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ParentDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountPhoneNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountPhoneNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccountPhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(Windows::Devices::Sms::CellularClass));
            *value = detach_from<Windows::Devices::Sms::CellularClass>(this->shim().CellularClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceStatus(Windows::Devices::Sms::SmsDeviceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceStatus, WINRT_WRAP(Windows::Devices::Sms::SmsDeviceStatus));
            *value = detach_from<Windows::Devices::Sms::SmsDeviceStatus>(this->shim().DeviceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CalculateLength(void* message, struct struct_Windows_Devices_Sms_SmsEncodedLength* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalculateLength, WINRT_WRAP(Windows::Devices::Sms::SmsEncodedLength), Windows::Devices::Sms::ISmsMessageBase const&);
            *value = detach_from<Windows::Devices::Sms::SmsEncodedLength>(this->shim().CalculateLength(*reinterpret_cast<Windows::Devices::Sms::ISmsMessageBase const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendMessageAndGetResultAsync(void* message, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAndGetResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsSendMessageResult>), Windows::Devices::Sms::ISmsMessageBase const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsSendMessageResult>>(this->shim().SendMessageAndGetResultAsync(*reinterpret_cast<Windows::Devices::Sms::ISmsMessageBase const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DeviceStatusChanged(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsDevice2, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().DeviceStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsDevice2, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeviceStatusChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeviceStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeviceStatusChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsDevice2Statics> : produce_base<D, Windows::Devices::Sms::ISmsDevice2Statics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromId(void* deviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Devices::Sms::SmsDevice2), hstring const&);
            *value = detach_from<Windows::Devices::Sms::SmsDevice2>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sms::SmsDevice2));
            *value = detach_from<Windows::Devices::Sms::SmsDevice2>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromParentId(void* parentDeviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromParentId, WINRT_WRAP(Windows::Devices::Sms::SmsDevice2), hstring const&);
            *value = detach_from<Windows::Devices::Sms::SmsDevice2>(this->shim().FromParentId(*reinterpret_cast<hstring const*>(&parentDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsDeviceMessageStore> : produce_base<D, Windows::Devices::Sms::ISmsDeviceMessageStore>
{
    int32_t WINRT_CALL DeleteMessageAsync(uint32_t messageId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), uint32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteMessageAsync(messageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteMessagesAsync(Windows::Devices::Sms::SmsMessageFilter messageFilter, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteMessagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::Sms::SmsMessageFilter const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteMessagesAsync(*reinterpret_cast<Windows::Devices::Sms::SmsMessageFilter const*>(&messageFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageAsync(uint32_t messageId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::ISmsMessage>), uint32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::ISmsMessage>>(this->shim().GetMessageAsync(messageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessagesAsync(Windows::Devices::Sms::SmsMessageFilter messageFilter, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsMessage>, int32_t>), Windows::Devices::Sms::SmsMessageFilter const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsMessage>, int32_t>>(this->shim().GetMessagesAsync(*reinterpret_cast<Windows::Devices::Sms::SmsMessageFilter const*>(&messageFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxMessages(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMessages, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsDeviceStatics> : produce_base<D, Windows::Devices::Sms::ISmsDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** phstrDeviceClassSelector) noexcept final
    {
        try
        {
            *phstrDeviceClassSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *phstrDeviceClassSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsDeviceStatics2> : produce_base<D, Windows::Devices::Sms::ISmsDeviceStatics2>
{
    int32_t WINRT_CALL FromNetworkAccountIdAsync(void* networkAccountId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromNetworkAccountIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice>>(this->shim().FromNetworkAccountIdAsync(*reinterpret_cast<hstring const*>(&networkAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsFilterRule> : produce_base<D, Windows::Devices::Sms::ISmsFilterRule>
{
    int32_t WINRT_CALL get_MessageType(Windows::Devices::Sms::SmsMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(Windows::Devices::Sms::SmsMessageType));
            *value = detach_from<Windows::Devices::Sms::SmsMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImsiPrefixes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImsiPrefixes, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ImsiPrefixes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().DeviceIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SenderNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SenderNumbers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SenderNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextMessagePrefixes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextMessagePrefixes, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().TextMessagePrefixes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PortNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PortNumbers, WINRT_WRAP(Windows::Foundation::Collections::IVector<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<int32_t>>(this->shim().PortNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(Windows::Devices::Sms::CellularClass));
            *value = detach_from<Windows::Devices::Sms::CellularClass>(this->shim().CellularClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CellularClass(Windows::Devices::Sms::CellularClass value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(void), Windows::Devices::Sms::CellularClass const&);
            this->shim().CellularClass(*reinterpret_cast<Windows::Devices::Sms::CellularClass const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<int32_t>>(this->shim().ProtocolIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TeleserviceIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TeleserviceIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<int32_t>>(this->shim().TeleserviceIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WapApplicationIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WapApplicationIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().WapApplicationIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WapContentTypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WapContentTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().WapContentTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastTypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsBroadcastType>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsBroadcastType>>(this->shim().BroadcastTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastChannels(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastChannels, WINRT_WRAP(Windows::Foundation::Collections::IVector<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<int32_t>>(this->shim().BroadcastChannels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsFilterRuleFactory> : produce_base<D, Windows::Devices::Sms::ISmsFilterRuleFactory>
{
    int32_t WINRT_CALL CreateFilterRule(Windows::Devices::Sms::SmsMessageType messageType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFilterRule, WINRT_WRAP(Windows::Devices::Sms::SmsFilterRule), Windows::Devices::Sms::SmsMessageType const&);
            *value = detach_from<Windows::Devices::Sms::SmsFilterRule>(this->shim().CreateFilterRule(*reinterpret_cast<Windows::Devices::Sms::SmsMessageType const*>(&messageType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsFilterRules> : produce_base<D, Windows::Devices::Sms::ISmsFilterRules>
{
    int32_t WINRT_CALL get_ActionType(Windows::Devices::Sms::SmsFilterActionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActionType, WINRT_WRAP(Windows::Devices::Sms::SmsFilterActionType));
            *value = detach_from<Windows::Devices::Sms::SmsFilterActionType>(this->shim().ActionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rules(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rules, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsFilterRule>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Sms::SmsFilterRule>>(this->shim().Rules());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsFilterRulesFactory> : produce_base<D, Windows::Devices::Sms::ISmsFilterRulesFactory>
{
    int32_t WINRT_CALL CreateFilterRules(Windows::Devices::Sms::SmsFilterActionType actionType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFilterRules, WINRT_WRAP(Windows::Devices::Sms::SmsFilterRules), Windows::Devices::Sms::SmsFilterActionType const&);
            *value = detach_from<Windows::Devices::Sms::SmsFilterRules>(this->shim().CreateFilterRules(*reinterpret_cast<Windows::Devices::Sms::SmsFilterActionType const*>(&actionType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsMessage> : produce_base<D, Windows::Devices::Sms::ISmsMessage>
{
    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageClass(Windows::Devices::Sms::SmsMessageClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageClass, WINRT_WRAP(Windows::Devices::Sms::SmsMessageClass));
            *value = detach_from<Windows::Devices::Sms::SmsMessageClass>(this->shim().MessageClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsMessageBase> : produce_base<D, Windows::Devices::Sms::ISmsMessageBase>
{
    int32_t WINRT_CALL get_MessageType(Windows::Devices::Sms::SmsMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(Windows::Devices::Sms::SmsMessageType));
            *value = detach_from<Windows::Devices::Sms::SmsMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(Windows::Devices::Sms::CellularClass));
            *value = detach_from<Windows::Devices::Sms::CellularClass>(this->shim().CellularClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageClass(Windows::Devices::Sms::SmsMessageClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageClass, WINRT_WRAP(Windows::Devices::Sms::SmsMessageClass));
            *value = detach_from<Windows::Devices::Sms::SmsMessageClass>(this->shim().MessageClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimIccId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimIccId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SimIccId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsMessageReceivedEventArgs> : produce_base<D, Windows::Devices::Sms::ISmsMessageReceivedEventArgs>
{
    int32_t WINRT_CALL get_TextMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextMessage, WINRT_WRAP(Windows::Devices::Sms::SmsTextMessage));
            *value = detach_from<Windows::Devices::Sms::SmsTextMessage>(this->shim().TextMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BinaryMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BinaryMessage, WINRT_WRAP(Windows::Devices::Sms::SmsBinaryMessage));
            *value = detach_from<Windows::Devices::Sms::SmsBinaryMessage>(this->shim().BinaryMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails> : produce_base<D, Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails>
{
    int32_t WINRT_CALL get_MessageType(Windows::Devices::Sms::SmsMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(Windows::Devices::Sms::SmsMessageType));
            *value = detach_from<Windows::Devices::Sms::SmsMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextMessage, WINRT_WRAP(Windows::Devices::Sms::SmsTextMessage2));
            *value = detach_from<Windows::Devices::Sms::SmsTextMessage2>(this->shim().TextMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WapMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WapMessage, WINRT_WRAP(Windows::Devices::Sms::SmsWapMessage));
            *value = detach_from<Windows::Devices::Sms::SmsWapMessage>(this->shim().WapMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMessage, WINRT_WRAP(Windows::Devices::Sms::SmsAppMessage));
            *value = detach_from<Windows::Devices::Sms::SmsAppMessage>(this->shim().AppMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastMessage, WINRT_WRAP(Windows::Devices::Sms::SmsBroadcastMessage));
            *value = detach_from<Windows::Devices::Sms::SmsBroadcastMessage>(this->shim().BroadcastMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VoicemailMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VoicemailMessage, WINRT_WRAP(Windows::Devices::Sms::SmsVoicemailMessage));
            *value = detach_from<Windows::Devices::Sms::SmsVoicemailMessage>(this->shim().VoicemailMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StatusMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusMessage, WINRT_WRAP(Windows::Devices::Sms::SmsStatusMessage));
            *value = detach_from<Windows::Devices::Sms::SmsStatusMessage>(this->shim().StatusMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Drop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Drop, WINRT_WRAP(void));
            this->shim().Drop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Accept() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accept, WINRT_WRAP(void));
            this->shim().Accept();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsMessageRegistration> : produce_base<D, Windows::Devices::Sms::ISmsMessageRegistration>
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

    int32_t WINRT_CALL Unregister() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unregister, WINRT_WRAP(void));
            this->shim().Unregister();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MessageReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsMessageRegistration, Windows::Devices::Sms::SmsMessageReceivedTriggerDetails> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sms::SmsMessageRegistration, Windows::Devices::Sms::SmsMessageReceivedTriggerDetails> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceived(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsMessageRegistrationStatics> : produce_base<D, Windows::Devices::Sms::ISmsMessageRegistrationStatics>
{
    int32_t WINRT_CALL get_AllRegistrations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllRegistrations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::SmsMessageRegistration>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::SmsMessageRegistration>>(this->shim().AllRegistrations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Register(void* id, void* filterRules, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Register, WINRT_WRAP(Windows::Devices::Sms::SmsMessageRegistration), hstring const&, Windows::Devices::Sms::SmsFilterRules const&);
            *value = detach_from<Windows::Devices::Sms::SmsMessageRegistration>(this->shim().Register(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Devices::Sms::SmsFilterRules const*>(&filterRules)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsReceivedEventDetails> : produce_base<D, Windows::Devices::Sms::ISmsReceivedEventDetails>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MessageIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsReceivedEventDetails2> : produce_base<D, Windows::Devices::Sms::ISmsReceivedEventDetails2>
{
    int32_t WINRT_CALL get_MessageClass(Windows::Devices::Sms::SmsMessageClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageClass, WINRT_WRAP(Windows::Devices::Sms::SmsMessageClass));
            *value = detach_from<Windows::Devices::Sms::SmsMessageClass>(this->shim().MessageClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BinaryMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BinaryMessage, WINRT_WRAP(Windows::Devices::Sms::SmsBinaryMessage));
            *value = detach_from<Windows::Devices::Sms::SmsBinaryMessage>(this->shim().BinaryMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsSendMessageResult> : produce_base<D, Windows::Devices::Sms::ISmsSendMessageResult>
{
    int32_t WINRT_CALL get_IsSuccessful(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuccessful, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuccessful());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageReferenceNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReferenceNumbers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<int32_t>>(this->shim().MessageReferenceNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(Windows::Devices::Sms::CellularClass));
            *value = detach_from<Windows::Devices::Sms::CellularClass>(this->shim().CellularClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModemErrorCode(Windows::Devices::Sms::SmsModemErrorCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModemErrorCode, WINRT_WRAP(Windows::Devices::Sms::SmsModemErrorCode));
            *value = detach_from<Windows::Devices::Sms::SmsModemErrorCode>(this->shim().ModemErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsErrorTransient(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsErrorTransient, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsErrorTransient());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkCauseCode(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkCauseCode, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NetworkCauseCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportFailureCause(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportFailureCause, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TransportFailureCause());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsStatusMessage> : produce_base<D, Windows::Devices::Sms::ISmsStatusMessage>
{
    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageReferenceNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReferenceNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MessageReferenceNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceCenterTimestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceCenterTimestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ServiceCenterTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DischargeTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DischargeTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DischargeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsTextMessage> : produce_base<D, Windows::Devices::Sms::ISmsTextMessage>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PartReferenceId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartReferenceId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PartReferenceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PartNumber(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartNumber, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PartNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PartCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PartCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), hstring const&);
            this->shim().To(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), hstring const&);
            this->shim().From(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Body(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(void), hstring const&);
            this->shim().Body(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Encoding(Windows::Devices::Sms::SmsEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encoding, WINRT_WRAP(Windows::Devices::Sms::SmsEncoding));
            *value = detach_from<Windows::Devices::Sms::SmsEncoding>(this->shim().Encoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Encoding(Windows::Devices::Sms::SmsEncoding value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encoding, WINRT_WRAP(void), Windows::Devices::Sms::SmsEncoding const&);
            this->shim().Encoding(*reinterpret_cast<Windows::Devices::Sms::SmsEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ToBinaryMessages(Windows::Devices::Sms::SmsDataFormat format, void** messages) noexcept final
    {
        try
        {
            *messages = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToBinaryMessages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsBinaryMessage>), Windows::Devices::Sms::SmsDataFormat const&);
            *messages = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::ISmsBinaryMessage>>(this->shim().ToBinaryMessages(*reinterpret_cast<Windows::Devices::Sms::SmsDataFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsTextMessage2> : produce_base<D, Windows::Devices::Sms::ISmsTextMessage2>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), hstring const&);
            this->shim().To(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Body(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(void), hstring const&);
            this->shim().Body(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Encoding(Windows::Devices::Sms::SmsEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encoding, WINRT_WRAP(Windows::Devices::Sms::SmsEncoding));
            *value = detach_from<Windows::Devices::Sms::SmsEncoding>(this->shim().Encoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Encoding(Windows::Devices::Sms::SmsEncoding value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Encoding, WINRT_WRAP(void), Windows::Devices::Sms::SmsEncoding const&);
            this->shim().Encoding(*reinterpret_cast<Windows::Devices::Sms::SmsEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CallbackNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallbackNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CallbackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CallbackNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallbackNumber, WINRT_WRAP(void), hstring const&);
            this->shim().CallbackNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDeliveryNotificationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDeliveryNotificationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDeliveryNotificationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDeliveryNotificationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDeliveryNotificationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsDeliveryNotificationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RetryAttemptCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetryAttemptCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RetryAttemptCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RetryAttemptCount(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetryAttemptCount, WINRT_WRAP(void), int32_t);
            this->shim().RetryAttemptCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TeleserviceId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TeleserviceId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TeleserviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ProtocolId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsTextMessageStatics> : produce_base<D, Windows::Devices::Sms::ISmsTextMessageStatics>
{
    int32_t WINRT_CALL FromBinaryMessage(void* binaryMessage, void** textMessage) noexcept final
    {
        try
        {
            *textMessage = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBinaryMessage, WINRT_WRAP(Windows::Devices::Sms::SmsTextMessage), Windows::Devices::Sms::SmsBinaryMessage const&);
            *textMessage = detach_from<Windows::Devices::Sms::SmsTextMessage>(this->shim().FromBinaryMessage(*reinterpret_cast<Windows::Devices::Sms::SmsBinaryMessage const*>(&binaryMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromBinaryData(Windows::Devices::Sms::SmsDataFormat format, uint32_t __valueSize, uint8_t* value, void** textMessage) noexcept final
    {
        try
        {
            *textMessage = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBinaryData, WINRT_WRAP(Windows::Devices::Sms::SmsTextMessage), Windows::Devices::Sms::SmsDataFormat const&, array_view<uint8_t const>);
            *textMessage = detach_from<Windows::Devices::Sms::SmsTextMessage>(this->shim().FromBinaryData(*reinterpret_cast<Windows::Devices::Sms::SmsDataFormat const*>(&format), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsVoicemailMessage> : produce_base<D, Windows::Devices::Sms::ISmsVoicemailMessage>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageCount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageCount, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().MessageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sms::ISmsWapMessage> : produce_base<D, Windows::Devices::Sms::ISmsWapMessage>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BinaryBody(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BinaryBody, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().BinaryBody());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Headers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headers, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Sms {

inline SmsAppMessage::SmsAppMessage() :
    SmsAppMessage(impl::call_factory<SmsAppMessage>([](auto&& f) { return f.template ActivateInstance<SmsAppMessage>(); }))
{}

inline SmsBinaryMessage::SmsBinaryMessage() :
    SmsBinaryMessage(impl::call_factory<SmsBinaryMessage>([](auto&& f) { return f.template ActivateInstance<SmsBinaryMessage>(); }))
{}

inline hstring SmsDevice::GetDeviceSelector()
{
    return impl::call_factory<SmsDevice, Windows::Devices::Sms::ISmsDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> SmsDevice::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<SmsDevice, Windows::Devices::Sms::ISmsDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> SmsDevice::GetDefaultAsync()
{
    return impl::call_factory<SmsDevice, Windows::Devices::Sms::ISmsDeviceStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sms::SmsDevice> SmsDevice::FromNetworkAccountIdAsync(param::hstring const& networkAccountId)
{
    return impl::call_factory<SmsDevice, Windows::Devices::Sms::ISmsDeviceStatics2>([&](auto&& f) { return f.FromNetworkAccountIdAsync(networkAccountId); });
}

inline hstring SmsDevice2::GetDeviceSelector()
{
    return impl::call_factory<SmsDevice2, Windows::Devices::Sms::ISmsDevice2Statics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Devices::Sms::SmsDevice2 SmsDevice2::FromId(param::hstring const& deviceId)
{
    return impl::call_factory<SmsDevice2, Windows::Devices::Sms::ISmsDevice2Statics>([&](auto&& f) { return f.FromId(deviceId); });
}

inline Windows::Devices::Sms::SmsDevice2 SmsDevice2::GetDefault()
{
    return impl::call_factory<SmsDevice2, Windows::Devices::Sms::ISmsDevice2Statics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Devices::Sms::SmsDevice2 SmsDevice2::FromParentId(param::hstring const& parentDeviceId)
{
    return impl::call_factory<SmsDevice2, Windows::Devices::Sms::ISmsDevice2Statics>([&](auto&& f) { return f.FromParentId(parentDeviceId); });
}

inline SmsFilterRule::SmsFilterRule(Windows::Devices::Sms::SmsMessageType const& messageType) :
    SmsFilterRule(impl::call_factory<SmsFilterRule, Windows::Devices::Sms::ISmsFilterRuleFactory>([&](auto&& f) { return f.CreateFilterRule(messageType); }))
{}

inline SmsFilterRules::SmsFilterRules(Windows::Devices::Sms::SmsFilterActionType const& actionType) :
    SmsFilterRules(impl::call_factory<SmsFilterRules, Windows::Devices::Sms::ISmsFilterRulesFactory>([&](auto&& f) { return f.CreateFilterRules(actionType); }))
{}

inline Windows::Foundation::Collections::IVectorView<Windows::Devices::Sms::SmsMessageRegistration> SmsMessageRegistration::AllRegistrations()
{
    return impl::call_factory<SmsMessageRegistration, Windows::Devices::Sms::ISmsMessageRegistrationStatics>([&](auto&& f) { return f.AllRegistrations(); });
}

inline Windows::Devices::Sms::SmsMessageRegistration SmsMessageRegistration::Register(param::hstring const& id, Windows::Devices::Sms::SmsFilterRules const& filterRules)
{
    return impl::call_factory<SmsMessageRegistration, Windows::Devices::Sms::ISmsMessageRegistrationStatics>([&](auto&& f) { return f.Register(id, filterRules); });
}

inline SmsTextMessage::SmsTextMessage() :
    SmsTextMessage(impl::call_factory<SmsTextMessage>([](auto&& f) { return f.template ActivateInstance<SmsTextMessage>(); }))
{}

inline Windows::Devices::Sms::SmsTextMessage SmsTextMessage::FromBinaryMessage(Windows::Devices::Sms::SmsBinaryMessage const& binaryMessage)
{
    return impl::call_factory<SmsTextMessage, Windows::Devices::Sms::ISmsTextMessageStatics>([&](auto&& f) { return f.FromBinaryMessage(binaryMessage); });
}

inline Windows::Devices::Sms::SmsTextMessage SmsTextMessage::FromBinaryData(Windows::Devices::Sms::SmsDataFormat const& format, array_view<uint8_t const> value)
{
    return impl::call_factory<SmsTextMessage, Windows::Devices::Sms::ISmsTextMessageStatics>([&](auto&& f) { return f.FromBinaryData(format, value); });
}

inline SmsTextMessage2::SmsTextMessage2() :
    SmsTextMessage2(impl::call_factory<SmsTextMessage2>([](auto&& f) { return f.template ActivateInstance<SmsTextMessage2>(); }))
{}

template <typename L> SmsDeviceStatusChangedEventHandler::SmsDeviceStatusChangedEventHandler(L handler) :
    SmsDeviceStatusChangedEventHandler(impl::make_delegate<SmsDeviceStatusChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> SmsDeviceStatusChangedEventHandler::SmsDeviceStatusChangedEventHandler(F* handler) :
    SmsDeviceStatusChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SmsDeviceStatusChangedEventHandler::SmsDeviceStatusChangedEventHandler(O* object, M method) :
    SmsDeviceStatusChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SmsDeviceStatusChangedEventHandler::SmsDeviceStatusChangedEventHandler(com_ptr<O>&& object, M method) :
    SmsDeviceStatusChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SmsDeviceStatusChangedEventHandler::SmsDeviceStatusChangedEventHandler(weak_ref<O>&& object, M method) :
    SmsDeviceStatusChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SmsDeviceStatusChangedEventHandler::operator()(Windows::Devices::Sms::SmsDevice const& sender) const
{
    check_hresult((*(impl::abi_t<SmsDeviceStatusChangedEventHandler>**)this)->Invoke(get_abi(sender)));
}

template <typename L> SmsMessageReceivedEventHandler::SmsMessageReceivedEventHandler(L handler) :
    SmsMessageReceivedEventHandler(impl::make_delegate<SmsMessageReceivedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> SmsMessageReceivedEventHandler::SmsMessageReceivedEventHandler(F* handler) :
    SmsMessageReceivedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SmsMessageReceivedEventHandler::SmsMessageReceivedEventHandler(O* object, M method) :
    SmsMessageReceivedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SmsMessageReceivedEventHandler::SmsMessageReceivedEventHandler(com_ptr<O>&& object, M method) :
    SmsMessageReceivedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SmsMessageReceivedEventHandler::SmsMessageReceivedEventHandler(weak_ref<O>&& object, M method) :
    SmsMessageReceivedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SmsMessageReceivedEventHandler::operator()(Windows::Devices::Sms::SmsDevice const& sender, Windows::Devices::Sms::SmsMessageReceivedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<SmsMessageReceivedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Sms::ISmsAppMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsAppMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsBinaryMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsBinaryMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsBroadcastMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsBroadcastMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsDevice> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsDevice2> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsDevice2> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsDevice2Statics> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsDevice2Statics> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsDeviceMessageStore> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsDeviceMessageStore> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsDeviceStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsDeviceStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsFilterRule> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsFilterRule> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsFilterRuleFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsFilterRuleFactory> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsFilterRules> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsFilterRules> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsFilterRulesFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsFilterRulesFactory> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsMessageBase> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsMessageBase> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsMessageReceivedTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsMessageRegistration> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsMessageRegistration> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsMessageRegistrationStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsMessageRegistrationStatics> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsReceivedEventDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsReceivedEventDetails> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsReceivedEventDetails2> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsReceivedEventDetails2> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsSendMessageResult> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsSendMessageResult> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsStatusMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsStatusMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsTextMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsTextMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsTextMessage2> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsTextMessage2> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsTextMessageStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsTextMessageStatics> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsVoicemailMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsVoicemailMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::ISmsWapMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::ISmsWapMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::DeleteSmsMessageOperation> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::DeleteSmsMessageOperation> {};
template<> struct hash<winrt::Windows::Devices::Sms::DeleteSmsMessagesOperation> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::DeleteSmsMessagesOperation> {};
template<> struct hash<winrt::Windows::Devices::Sms::GetSmsDeviceOperation> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::GetSmsDeviceOperation> {};
template<> struct hash<winrt::Windows::Devices::Sms::GetSmsMessageOperation> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::GetSmsMessageOperation> {};
template<> struct hash<winrt::Windows::Devices::Sms::GetSmsMessagesOperation> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::GetSmsMessagesOperation> {};
template<> struct hash<winrt::Windows::Devices::Sms::SendSmsMessageOperation> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SendSmsMessageOperation> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsAppMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsAppMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsBinaryMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsBinaryMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsBroadcastMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsBroadcastMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsDevice> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsDevice2> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsDevice2> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsDeviceMessageStore> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsDeviceMessageStore> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsFilterRule> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsFilterRule> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsFilterRules> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsFilterRules> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsMessageReceivedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsMessageReceivedTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsMessageRegistration> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsMessageRegistration> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsReceivedEventDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsReceivedEventDetails> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsSendMessageResult> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsSendMessageResult> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsStatusMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsStatusMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsTextMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsTextMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsTextMessage2> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsTextMessage2> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsVoicemailMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsVoicemailMessage> {};
template<> struct hash<winrt::Windows::Devices::Sms::SmsWapMessage> : winrt::impl::hash_base<winrt::Windows::Devices::Sms::SmsWapMessage> {};

}
