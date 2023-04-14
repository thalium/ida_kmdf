// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.Miracast.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::Miracast::MiracastReceiverSettings consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetDefaultSettings() const
{
    Windows::Media::Miracast::MiracastReceiverSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->GetDefaultSettings(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverSettings consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetCurrentSettings() const
{
    Windows::Media::Miracast::MiracastReceiverSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->GetCurrentSettings(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSettings> consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetCurrentSettingsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSettings> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->GetCurrentSettingsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverApplySettingsResult consume_Windows_Media_Miracast_IMiracastReceiver<D>::DisconnectAllAndApplySettings(Windows::Media::Miracast::MiracastReceiverSettings const& settings) const
{
    Windows::Media::Miracast::MiracastReceiverApplySettingsResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->DisconnectAllAndApplySettings(get_abi(settings), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverApplySettingsResult> consume_Windows_Media_Miracast_IMiracastReceiver<D>::DisconnectAllAndApplySettingsAsync(Windows::Media::Miracast::MiracastReceiverSettings const& settings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverApplySettingsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->DisconnectAllAndApplySettingsAsync(get_abi(settings), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverStatus consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetStatus() const
{
    Windows::Media::Miracast::MiracastReceiverStatus result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->GetStatus(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverStatus> consume_Windows_Media_Miracast_IMiracastReceiver<D>::GetStatusAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->GetStatusAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->add_StatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged_revoker consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiver<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->remove_StatusChanged(get_abi(token)));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverSession consume_Windows_Media_Miracast_IMiracastReceiver<D>::CreateSession(Windows::ApplicationModel::Core::CoreApplicationView const& view) const
{
    Windows::Media::Miracast::MiracastReceiverSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->CreateSession(get_abi(view), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSession> consume_Windows_Media_Miracast_IMiracastReceiver<D>::CreateSessionAsync(Windows::ApplicationModel::Core::CoreApplicationView const& view) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSession> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->CreateSessionAsync(get_abi(view), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiver<D>::ClearKnownTransmitters() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->ClearKnownTransmitters());
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiver<D>::RemoveKnownTransmitter(Windows::Media::Miracast::MiracastTransmitter const& transmitter) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiver)->RemoveKnownTransmitter(get_abi(transmitter)));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverApplySettingsStatus consume_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult<D>::Status() const
{
    Windows::Media::Miracast::MiracastReceiverApplySettingsStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverApplySettingsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverApplySettingsResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Disconnect(Windows::Media::Miracast::MiracastReceiverDisconnectReason const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->Disconnect(get_abi(reason)));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Disconnect(Windows::Media::Miracast::MiracastReceiverDisconnectReason const& reason, param::hstring const& message) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->DisconnectWithMessage(get_abi(reason), get_abi(message)));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->Pause());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::PauseAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->PauseAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->Resume());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::ResumeAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->ResumeAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Miracast::MiracastTransmitter consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::Transmitter() const
{
    Windows::Media::Miracast::MiracastTransmitter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->get_Transmitter(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverInputDevices consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::InputDevices() const
{
    Windows::Media::Miracast::MiracastReceiverInputDevices value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->get_InputDevices(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverCursorImageChannel consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::CursorImageChannel() const
{
    Windows::Media::Miracast::MiracastReceiverCursorImageChannel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->get_CursorImageChannel(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverStreamControl consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>::StreamControl() const
{
    Windows::Media::Miracast::MiracastReceiverStreamControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnection)->get_StreamControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverConnection consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>::Connection() const
{
    Windows::Media::Miracast::MiracastReceiverConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>::Pin() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs)->get_Pin(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_IsEnabled(&value));
    return value;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::MaxImageSize() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_MaxImageSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::PointInt32 consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::Position() const
{
    Windows::Graphics::PointInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStream() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->get_ImageStream(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->add_ImageStreamChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged_revoker consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ImageStreamChanged_revoker>(this, ImageStreamChanged(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::ImageStreamChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->remove_ImageStreamChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->add_PositionChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged_revoker consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>::PositionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannel)->remove_PositionChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->put_IsEnabled(value));
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::MaxImageSize() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->get_MaxImageSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>::MaxImageSize(Windows::Graphics::SizeInt32 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings)->put_MaxImageSize(get_abi(value)));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverConnection consume_Windows_Media_Miracast_IMiracastReceiverDisconnectedEventArgs<D>::Connection() const
{
    Windows::Media::Miracast::MiracastReceiverConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::TransmitInput() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_TransmitInput(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::TransmitInput(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->put_TransmitInput(value));
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::IsRequestedByTransmitter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_IsRequestedByTransmitter(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::IsTransmittingInput() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_IsTransmittingInput(&value));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Mode() const
{
    Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Mode(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->put_Mode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverGameControllerDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed_revoker consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverGameControllerDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverGameControllerDevice)->remove_Changed(get_abi(token)));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverKeyboardDevice consume_Windows_Media_Miracast_IMiracastReceiverInputDevices<D>::Keyboard() const
{
    Windows::Media::Miracast::MiracastReceiverKeyboardDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverInputDevices)->get_Keyboard(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverGameControllerDevice consume_Windows_Media_Miracast_IMiracastReceiverInputDevices<D>::GameController() const
{
    Windows::Media::Miracast::MiracastReceiverGameControllerDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverInputDevices)->get_GameController(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::TransmitInput() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->get_TransmitInput(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::TransmitInput(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->put_TransmitInput(value));
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::IsRequestedByTransmitter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->get_IsRequestedByTransmitter(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::IsTransmittingInput() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->get_IsTransmittingInput(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverKeyboardDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed_revoker consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverKeyboardDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverKeyboardDevice)->remove_Changed(get_abi(token)));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverConnection consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::Connection() const
{
    Windows::Media::Miracast::MiracastReceiverConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::MediaSource() const
{
    Windows::Media::Core::MediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->get_MediaSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::CursorImageChannelSettings() const
{
    Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->get_CursorImageChannelSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->add_ConnectionCreated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated_revoker consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ConnectionCreated_revoker>(this, ConnectionCreated(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::ConnectionCreated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->remove_ConnectionCreated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->add_MediaSourceCreated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated_revoker consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MediaSourceCreated_revoker>(this, MediaSourceCreated(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MediaSourceCreated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->remove_MediaSourceCreated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->add_Disconnected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected_revoker consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Disconnected_revoker>(this, Disconnected(handler));
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Disconnected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->remove_Disconnected(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::AllowConnectionTakeover() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->get_AllowConnectionTakeover(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::AllowConnectionTakeover(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->put_AllowConnectionTakeover(value));
}

template <typename D> int32_t consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MaxSimultaneousConnections() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->get_MaxSimultaneousConnections(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::MaxSimultaneousConnections(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->put_MaxSimultaneousConnections(value));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverSessionStartResult consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::Start() const
{
    Windows::Media::Miracast::MiracastReceiverSessionStartResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->Start(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSessionStartResult> consume_Windows_Media_Miracast_IMiracastReceiverSession<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSessionStartResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSession)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverSessionStartStatus consume_Windows_Media_Miracast_IMiracastReceiverSessionStartResult<D>::Status() const
{
    Windows::Media::Miracast::MiracastReceiverSessionStartStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSessionStartResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Miracast_IMiracastReceiverSessionStartResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSessionStartResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::FriendlyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->put_FriendlyName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->get_ModelName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->put_ModelName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->get_ModelNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::ModelNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->put_ModelNumber(get_abi(value)));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverAuthorizationMethod consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::AuthorizationMethod() const
{
    Windows::Media::Miracast::MiracastReceiverAuthorizationMethod value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->get_AuthorizationMethod(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::AuthorizationMethod(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->put_AuthorizationMethod(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::RequireAuthorizationFromKnownTransmitters() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->get_RequireAuthorizationFromKnownTransmitters(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>::RequireAuthorizationFromKnownTransmitters(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverSettings)->put_RequireAuthorizationFromKnownTransmitters(value));
}

template <typename D> Windows::Media::Miracast::MiracastReceiverListeningStatus consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::ListeningStatus() const
{
    Windows::Media::Miracast::MiracastReceiverListeningStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStatus)->get_ListeningStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverWiFiStatus consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::WiFiStatus() const
{
    Windows::Media::Miracast::MiracastReceiverWiFiStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStatus)->get_WiFiStatus(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::IsConnectionTakeoverSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStatus)->get_IsConnectionTakeoverSupported(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::MaxSimultaneousConnections() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStatus)->get_MaxSimultaneousConnections(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastTransmitter> consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>::KnownTransmitters() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastTransmitter> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStatus)->get_KnownTransmitters(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Miracast::MiracastReceiverVideoStreamSettings consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::GetVideoStreamSettings() const
{
    Windows::Media::Miracast::MiracastReceiverVideoStreamSettings result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStreamControl)->GetVideoStreamSettings(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings> consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::GetVideoStreamSettingsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStreamControl)->GetVideoStreamSettingsAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::SuggestVideoStreamSettings(Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const& settings) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStreamControl)->SuggestVideoStreamSettings(get_abi(settings)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::SuggestVideoStreamSettingsAsync(Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const& settings) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStreamControl)->SuggestVideoStreamSettingsAsync(get_abi(settings), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::MuteAudio() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStreamControl)->get_MuteAudio(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>::MuteAudio(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverStreamControl)->put_MuteAudio(value));
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Size() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Size(Windows::Graphics::SizeInt32 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->put_Size(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Bitrate() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->get_Bitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>::Bitrate(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings)->put_Bitrate(value));
}

template <typename D> hstring consume_Windows_Media_Miracast_IMiracastTransmitter<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastTransmitter<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->put_Name(get_abi(value)));
}

template <typename D> Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus consume_Windows_Media_Miracast_IMiracastTransmitter<D>::AuthorizationStatus() const
{
    Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->get_AuthorizationStatus(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Miracast_IMiracastTransmitter<D>::AuthorizationStatus(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->put_AuthorizationStatus(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastReceiverConnection> consume_Windows_Media_Miracast_IMiracastTransmitter<D>::GetConnections() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastReceiverConnection> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->GetConnections(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Media_Miracast_IMiracastTransmitter<D>::MacAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->get_MacAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Miracast_IMiracastTransmitter<D>::LastConnectionTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Miracast::IMiracastTransmitter)->get_LastConnectionTime(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiver> : produce_base<D, Windows::Media::Miracast::IMiracastReceiver>
{
    int32_t WINRT_CALL GetDefaultSettings(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultSettings, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverSettings));
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverSettings>(this->shim().GetDefaultSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentSettings(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSettings, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverSettings));
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentSettingsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSettings>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSettings>>(this->shim().GetCurrentSettingsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisconnectAllAndApplySettings(void* settings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectAllAndApplySettings, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverApplySettingsResult), Windows::Media::Miracast::MiracastReceiverSettings const&);
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverApplySettingsResult>(this->shim().DisconnectAllAndApplySettings(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisconnectAllAndApplySettingsAsync(void* settings, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectAllAndApplySettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverApplySettingsResult>), Windows::Media::Miracast::MiracastReceiverSettings const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverApplySettingsResult>>(this->shim().DisconnectAllAndApplySettingsAsync(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatus(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatus, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverStatus));
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverStatus>(this->shim().GetStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStatusAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverStatus>>(this->shim().GetStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiver, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiver, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CreateSession(void* view, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSession, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverSession), Windows::ApplicationModel::Core::CoreApplicationView const&);
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverSession>(this->shim().CreateSession(*reinterpret_cast<Windows::ApplicationModel::Core::CoreApplicationView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSessionAsync(void* view, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSessionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSession>), Windows::ApplicationModel::Core::CoreApplicationView const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSession>>(this->shim().CreateSessionAsync(*reinterpret_cast<Windows::ApplicationModel::Core::CoreApplicationView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearKnownTransmitters() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearKnownTransmitters, WINRT_WRAP(void));
            this->shim().ClearKnownTransmitters();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveKnownTransmitter(void* transmitter) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveKnownTransmitter, WINRT_WRAP(void), Windows::Media::Miracast::MiracastTransmitter const&);
            this->shim().RemoveKnownTransmitter(*reinterpret_cast<Windows::Media::Miracast::MiracastTransmitter const*>(&transmitter));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverApplySettingsResult> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverApplySettingsResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::Miracast::MiracastReceiverApplySettingsStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverApplySettingsStatus));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverApplySettingsStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverConnection> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverConnection>
{
    int32_t WINRT_CALL Disconnect(Windows::Media::Miracast::MiracastReceiverDisconnectReason reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disconnect, WINRT_WRAP(void), Windows::Media::Miracast::MiracastReceiverDisconnectReason const&);
            this->shim().Disconnect(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverDisconnectReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisconnectWithMessage(Windows::Media::Miracast::MiracastReceiverDisconnectReason reason, void* message) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disconnect, WINRT_WRAP(void), Windows::Media::Miracast::MiracastReceiverDisconnectReason const&, hstring const&);
            this->shim().Disconnect(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverDisconnectReason const*>(&reason), *reinterpret_cast<hstring const*>(&message));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resume() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resume, WINRT_WRAP(void));
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResumeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transmitter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transmitter, WINRT_WRAP(Windows::Media::Miracast::MiracastTransmitter));
            *value = detach_from<Windows::Media::Miracast::MiracastTransmitter>(this->shim().Transmitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputDevices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDevices, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverInputDevices));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverInputDevices>(this->shim().InputDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CursorImageChannel(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorImageChannel, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverCursorImageChannel));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverCursorImageChannel>(this->shim().CursorImageChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamControl, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverStreamControl));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverStreamControl>(this->shim().StreamControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverConnection));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pin(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pin, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverCursorImageChannel> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxImageSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxImageSize, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().MaxImageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(struct struct_Windows_Graphics_PointInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Graphics::PointInt32));
            *value = detach_from<Windows::Graphics::PointInt32>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageStream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().ImageStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ImageStreamChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageStreamChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ImageStreamChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ImageStreamChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ImageStreamChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ImageStreamChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PositionChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PositionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxImageSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxImageSize, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().MaxImageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxImageSize(struct struct_Windows_Graphics_SizeInt32 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxImageSize, WINRT_WRAP(void), Windows::Graphics::SizeInt32 const&);
            this->shim().MaxImageSize(*reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverConnection));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverGameControllerDevice> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>
{
    int32_t WINRT_CALL get_TransmitInput(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitInput, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TransmitInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransmitInput(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitInput, WINRT_WRAP(void), bool);
            this->shim().TransmitInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRequestedByTransmitter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequestedByTransmitter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRequestedByTransmitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransmittingInput(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransmittingInput, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransmittingInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverGameControllerDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverGameControllerDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverInputDevices> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverInputDevices>
{
    int32_t WINRT_CALL get_Keyboard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Keyboard, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverKeyboardDevice));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverKeyboardDevice>(this->shim().Keyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GameController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameController, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverGameControllerDevice));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverGameControllerDevice>(this->shim().GameController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverKeyboardDevice> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>
{
    int32_t WINRT_CALL get_TransmitInput(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitInput, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TransmitInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransmitInput(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmitInput, WINRT_WRAP(void), bool);
            this->shim().TransmitInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRequestedByTransmitter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequestedByTransmitter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRequestedByTransmitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransmittingInput(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransmittingInput, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransmittingInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverKeyboardDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverKeyboardDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverConnection));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaSource, WINRT_WRAP(Windows::Media::Core::MediaSource));
            *value = detach_from<Windows::Media::Core::MediaSource>(this->shim().MediaSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CursorImageChannelSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorImageChannelSettings, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings>(this->shim().CursorImageChannelSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverSession> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverSession>
{
    int32_t WINRT_CALL add_ConnectionCreated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionCreated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ConnectionCreated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ConnectionCreated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ConnectionCreated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ConnectionCreated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MediaSourceCreated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaSourceCreated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MediaSourceCreated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MediaSourceCreated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MediaSourceCreated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MediaSourceCreated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Disconnected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disconnected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Disconnected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Disconnected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Disconnected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Disconnected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_AllowConnectionTakeover(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowConnectionTakeover, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowConnectionTakeover());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowConnectionTakeover(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowConnectionTakeover, WINRT_WRAP(void), bool);
            this->shim().AllowConnectionTakeover(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSimultaneousConnections(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSimultaneousConnections, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxSimultaneousConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxSimultaneousConnections(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSimultaneousConnections, WINRT_WRAP(void), int32_t);
            this->shim().MaxSimultaneousConnections(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverSessionStartResult));
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverSessionStartResult>(this->shim().Start());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSessionStartResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSessionStartResult>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverSessionStartResult> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverSessionStartResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::Miracast::MiracastReceiverSessionStartStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverSessionStartStatus));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverSessionStartStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverSettings> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverSettings>
{
    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FriendlyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(void), hstring const&);
            this->shim().FriendlyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ModelName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelName, WINRT_WRAP(void), hstring const&);
            this->shim().ModelName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ModelNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumber, WINRT_WRAP(void), hstring const&);
            this->shim().ModelNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthorizationMethod(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthorizationMethod, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverAuthorizationMethod>(this->shim().AuthorizationMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthorizationMethod(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthorizationMethod, WINRT_WRAP(void), Windows::Media::Miracast::MiracastReceiverAuthorizationMethod const&);
            this->shim().AuthorizationMethod(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverAuthorizationMethod const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequireAuthorizationFromKnownTransmitters(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequireAuthorizationFromKnownTransmitters, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RequireAuthorizationFromKnownTransmitters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequireAuthorizationFromKnownTransmitters(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequireAuthorizationFromKnownTransmitters, WINRT_WRAP(void), bool);
            this->shim().RequireAuthorizationFromKnownTransmitters(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverStatus> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverStatus>
{
    int32_t WINRT_CALL get_ListeningStatus(Windows::Media::Miracast::MiracastReceiverListeningStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListeningStatus, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverListeningStatus));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverListeningStatus>(this->shim().ListeningStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WiFiStatus(Windows::Media::Miracast::MiracastReceiverWiFiStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WiFiStatus, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverWiFiStatus));
            *value = detach_from<Windows::Media::Miracast::MiracastReceiverWiFiStatus>(this->shim().WiFiStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConnectionTakeoverSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConnectionTakeoverSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConnectionTakeoverSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSimultaneousConnections(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSimultaneousConnections, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxSimultaneousConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KnownTransmitters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KnownTransmitters, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastTransmitter>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastTransmitter>>(this->shim().KnownTransmitters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverStreamControl> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverStreamControl>
{
    int32_t WINRT_CALL GetVideoStreamSettings(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoStreamSettings, WINRT_WRAP(Windows::Media::Miracast::MiracastReceiverVideoStreamSettings));
            *result = detach_from<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>(this->shim().GetVideoStreamSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVideoStreamSettingsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoStreamSettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>>(this->shim().GetVideoStreamSettingsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SuggestVideoStreamSettings(void* settings) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestVideoStreamSettings, WINRT_WRAP(void), Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const&);
            this->shim().SuggestVideoStreamSettings(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SuggestVideoStreamSettingsAsync(void* settings, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestVideoStreamSettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SuggestVideoStreamSettingsAsync(*reinterpret_cast<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MuteAudio(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MuteAudio, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().MuteAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MuteAudio(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MuteAudio, WINRT_WRAP(void), bool);
            this->shim().MuteAudio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings> : produce_base<D, Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings>
{
    int32_t WINRT_CALL get_Size(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(struct struct_Windows_Graphics_SizeInt32 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Graphics::SizeInt32 const&);
            this->shim().Size(*reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitrate(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bitrate(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(void), int32_t);
            this->shim().Bitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Miracast::IMiracastTransmitter> : produce_base<D, Windows::Media::Miracast::IMiracastTransmitter>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthorizationStatus(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthorizationStatus, WINRT_WRAP(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus));
            *value = detach_from<Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus>(this->shim().AuthorizationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthorizationStatus(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthorizationStatus, WINRT_WRAP(void), Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus const&);
            this->shim().AuthorizationStatus(*reinterpret_cast<Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConnections(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastReceiverConnection>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastReceiverConnection>>(this->shim().GetConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MacAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MacAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MacAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastConnectionTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastConnectionTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastConnectionTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Miracast {

inline MiracastReceiver::MiracastReceiver() :
    MiracastReceiver(impl::call_factory<MiracastReceiver>([](auto&& f) { return f.template ActivateInstance<MiracastReceiver>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiver> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiver> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverConnection> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverConnection> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverInputDevices> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverSession> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverSession> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverSessionStartResult> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverSettings> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverSettings> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverStatus> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverStatus> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverStreamControl> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings> {};
template<> struct hash<winrt::Windows::Media::Miracast::IMiracastTransmitter> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::IMiracastTransmitter> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiver> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiver> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverApplySettingsResult> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverConnection> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverConnection> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannel> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverGameControllerDevice> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverInputDevices> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverInputDevices> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverKeyboardDevice> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverSession> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverSession> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverSessionStartResult> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverSettings> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverSettings> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverStatus> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverStatus> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverStreamControl> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverStreamControl> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings> {};
template<> struct hash<winrt::Windows::Media::Miracast::MiracastTransmitter> : winrt::impl::hash_base<winrt::Windows::Media::Miracast::MiracastTransmitter> {};

}
