// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.2.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_Media_IAudioBuffer<D>::Capacity() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::IAudioBuffer)->get_Capacity(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_IAudioBuffer<D>::Length() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::IAudioBuffer)->get_Length(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IAudioBuffer<D>::Length(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IAudioBuffer)->put_Length(value));
}

template <typename D> Windows::Media::AudioBuffer consume_Windows_Media_IAudioFrame<D>::LockBuffer(Windows::Media::AudioBufferAccessMode const& mode) const
{
    Windows::Media::AudioBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IAudioFrame)->LockBuffer(get_abi(mode), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::AudioFrame consume_Windows_Media_IAudioFrameFactory<D>::Create(uint32_t capacity) const
{
    Windows::Media::AudioFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IAudioFrameFactory)->Create(capacity, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaPlaybackAutoRepeatMode consume_Windows_Media_IAutoRepeatModeChangeRequestedEventArgs<D>::RequestedAutoRepeatMode() const
{
    Windows::Media::MediaPlaybackAutoRepeatMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::IAutoRepeatModeChangeRequestedEventArgs)->get_RequestedAutoRepeatMode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_IImageDisplayProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IImageDisplayProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IImageDisplayProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IImageDisplayProperties)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IImageDisplayProperties<D>::Subtitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IImageDisplayProperties)->get_Subtitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IImageDisplayProperties<D>::Subtitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IImageDisplayProperties)->put_Subtitle(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_SoundLevelChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::SoundLevelChanged_revoker consume_Windows_Media_IMediaControl<D>::SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SoundLevelChanged_revoker>(this, SoundLevelChanged(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::SoundLevelChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_SoundLevelChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::PlayPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_PlayPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::PlayPressed_revoker consume_Windows_Media_IMediaControl<D>::PlayPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PlayPressed_revoker>(this, PlayPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::PlayPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_PlayPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::PausePressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_PausePressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::PausePressed_revoker consume_Windows_Media_IMediaControl<D>::PausePressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PausePressed_revoker>(this, PausePressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::PausePressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_PausePressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::StopPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_StopPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::StopPressed_revoker consume_Windows_Media_IMediaControl<D>::StopPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StopPressed_revoker>(this, StopPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::StopPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_StopPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_PlayPauseTogglePressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed_revoker consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PlayPauseTogglePressed_revoker>(this, PlayPauseTogglePressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_PlayPauseTogglePressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::RecordPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_RecordPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::RecordPressed_revoker consume_Windows_Media_IMediaControl<D>::RecordPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RecordPressed_revoker>(this, RecordPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::RecordPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_RecordPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::NextTrackPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_NextTrackPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::NextTrackPressed_revoker consume_Windows_Media_IMediaControl<D>::NextTrackPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, NextTrackPressed_revoker>(this, NextTrackPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::NextTrackPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_NextTrackPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_PreviousTrackPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed_revoker consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PreviousTrackPressed_revoker>(this, PreviousTrackPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_PreviousTrackPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::FastForwardPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_FastForwardPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::FastForwardPressed_revoker consume_Windows_Media_IMediaControl<D>::FastForwardPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, FastForwardPressed_revoker>(this, FastForwardPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::FastForwardPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_FastForwardPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::RewindPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_RewindPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::RewindPressed_revoker consume_Windows_Media_IMediaControl<D>::RewindPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RewindPressed_revoker>(this, RewindPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::RewindPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_RewindPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::ChannelUpPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_ChannelUpPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::ChannelUpPressed_revoker consume_Windows_Media_IMediaControl<D>::ChannelUpPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ChannelUpPressed_revoker>(this, ChannelUpPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::ChannelUpPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_ChannelUpPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaControl<D>::ChannelDownPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->add_ChannelDownPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_IMediaControl<D>::ChannelDownPressed_revoker consume_Windows_Media_IMediaControl<D>::ChannelDownPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ChannelDownPressed_revoker>(this, ChannelDownPressed(handler));
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::ChannelDownPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaControl)->remove_ChannelDownPressed(get_abi(cookie)));
}

template <typename D> Windows::Media::SoundLevel consume_Windows_Media_IMediaControl<D>::SoundLevel() const
{
    Windows::Media::SoundLevel value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->get_SoundLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::TrackName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->put_TrackName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IMediaControl<D>::TrackName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->get_TrackName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::ArtistName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->put_ArtistName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IMediaControl<D>::ArtistName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->get_ArtistName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::IsPlaying(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->put_IsPlaying(value));
}

template <typename D> bool consume_Windows_Media_IMediaControl<D>::IsPlaying() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->get_IsPlaying(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaControl<D>::AlbumArt(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->put_AlbumArt(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_IMediaControl<D>::AlbumArt() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaControl)->get_AlbumArt(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaExtension<D>::SetProperties(Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtension)->SetProperties(get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterSchemeHandler(param::hstring const& activatableClassId, param::hstring const& scheme) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterSchemeHandler(get_abi(activatableClassId), get_abi(scheme)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterSchemeHandler(param::hstring const& activatableClassId, param::hstring const& scheme, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterSchemeHandlerWithSettings(get_abi(activatableClassId), get_abi(scheme), get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterByteStreamHandler(param::hstring const& activatableClassId, param::hstring const& fileExtension, param::hstring const& mimeType) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterByteStreamHandler(get_abi(activatableClassId), get_abi(fileExtension), get_abi(mimeType)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterByteStreamHandler(param::hstring const& activatableClassId, param::hstring const& fileExtension, param::hstring const& mimeType, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterByteStreamHandlerWithSettings(get_abi(activatableClassId), get_abi(fileExtension), get_abi(mimeType), get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterAudioDecoder(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterAudioDecoderWithSettings(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype), get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterAudioEncoder(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterAudioEncoderWithSettings(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype), get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterVideoDecoder(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterVideoDecoderWithSettings(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype), get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterVideoEncoder(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager)->RegisterVideoEncoderWithSettings(get_abi(activatableClassId), get_abi(inputSubtype), get_abi(outputSubtype), get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_IMediaExtensionManager2<D>::RegisterMediaExtensionForAppService(Windows::Media::IMediaExtension const& extension, Windows::ApplicationModel::AppService::AppServiceConnection const& connection) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaExtensionManager2)->RegisterMediaExtensionForAppService(get_abi(extension), get_abi(connection)));
}

template <typename D> hstring consume_Windows_Media_IMediaFrame<D>::Type() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_Type(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_IMediaFrame<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_IsReadOnly(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaFrame<D>::RelativeTime(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->put_RelativeTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_IMediaFrame<D>::RelativeTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_RelativeTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaFrame<D>::SystemRelativeTime(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->put_SystemRelativeTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_IMediaFrame<D>::SystemRelativeTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_SystemRelativeTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaFrame<D>::Duration(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_IMediaFrame<D>::Duration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaFrame<D>::IsDiscontinuous(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->put_IsDiscontinuous(value));
}

template <typename D> bool consume_Windows_Media_IMediaFrame<D>::IsDiscontinuous() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_IsDiscontinuous(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Media_IMediaFrame<D>::ExtendedProperties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaFrame)->get_ExtendedProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_IMediaMarker<D>::Time() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaMarker)->get_Time(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_IMediaMarker<D>::MediaMarkerType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaMarker)->get_MediaMarkerType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_IMediaMarker<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaMarker)->get_Text(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_IMediaMarkerTypesStatics<D>::Bookmark() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaMarkerTypesStatics)->get_Bookmark(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::IMediaMarker> consume_Windows_Media_IMediaMarkers<D>::Markers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::IMediaMarker> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaMarkers)->get_Markers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Media_IMediaProcessingTriggerDetails<D>::Arguments() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaProcessingTriggerDetails)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->Start());
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->Resume());
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->Pause());
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_IMediaTimelineController<D>::Position() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::Position(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->put_Position(get_abi(value)));
}

template <typename D> double consume_Windows_Media_IMediaTimelineController<D>::ClockRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->get_ClockRate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::ClockRate(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->put_ClockRate(value));
}

template <typename D> Windows::Media::MediaTimelineControllerState consume_Windows_Media_IMediaTimelineController<D>::State() const
{
    Windows::Media::MediaTimelineControllerState value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaTimelineController<D>::PositionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const& positionChangedEventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->add_PositionChanged(get_abi(positionChangedEventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Media_IMediaTimelineController<D>::PositionChanged_revoker consume_Windows_Media_IMediaTimelineController<D>::PositionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const& positionChangedEventHandler) const
{
    return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(positionChangedEventHandler));
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::PositionChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaTimelineController)->remove_PositionChanged(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaTimelineController<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const& stateChangedEventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController)->add_StateChanged(get_abi(stateChangedEventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Media_IMediaTimelineController<D>::StateChanged_revoker consume_Windows_Media_IMediaTimelineController<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const& stateChangedEventHandler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(stateChangedEventHandler));
}

template <typename D> void consume_Windows_Media_IMediaTimelineController<D>::StateChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaTimelineController)->remove_StateChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_IMediaTimelineController2<D>::Duration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController2)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaTimelineController2<D>::Duration(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController2)->put_Duration(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_IMediaTimelineController2<D>::IsLoopingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController2)->get_IsLoopingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IMediaTimelineController2<D>::IsLoopingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController2)->put_IsLoopingEnabled(value));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaTimelineController2<D>::Failed(Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Media::MediaTimelineControllerFailedEventArgs> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController2)->add_Failed(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_IMediaTimelineController2<D>::Failed_revoker consume_Windows_Media_IMediaTimelineController2<D>::Failed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Media::MediaTimelineControllerFailedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, Failed_revoker>(this, Failed(eventHandler));
}

template <typename D> void consume_Windows_Media_IMediaTimelineController2<D>::Failed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaTimelineController2)->remove_Failed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_IMediaTimelineController2<D>::Ended(Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineController2)->add_Ended(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_IMediaTimelineController2<D>::Ended_revoker consume_Windows_Media_IMediaTimelineController2<D>::Ended(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, Ended_revoker>(this, Ended(eventHandler));
}

template <typename D> void consume_Windows_Media_IMediaTimelineController2<D>::Ended(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::IMediaTimelineController2)->remove_Ended(get_abi(token)));
}

template <typename D> winrt::hresult consume_Windows_Media_IMediaTimelineControllerFailedEventArgs<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMediaTimelineControllerFailedEventArgs)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_IMusicDisplayProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMusicDisplayProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IMusicDisplayProperties<D>::AlbumArtist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties)->get_AlbumArtist(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMusicDisplayProperties<D>::AlbumArtist(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties)->put_AlbumArtist(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IMusicDisplayProperties<D>::Artist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties)->get_Artist(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMusicDisplayProperties<D>::Artist(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties)->put_Artist(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IMusicDisplayProperties2<D>::AlbumTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties2)->get_AlbumTitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IMusicDisplayProperties2<D>::AlbumTitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties2)->put_AlbumTitle(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Media_IMusicDisplayProperties2<D>::TrackNumber() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties2)->get_TrackNumber(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IMusicDisplayProperties2<D>::TrackNumber(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties2)->put_TrackNumber(value));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Media_IMusicDisplayProperties2<D>::Genres() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties2)->get_Genres(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_IMusicDisplayProperties3<D>::AlbumTrackCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties3)->get_AlbumTrackCount(&value));
    return value;
}

template <typename D> void consume_Windows_Media_IMusicDisplayProperties3<D>::AlbumTrackCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IMusicDisplayProperties3)->put_AlbumTrackCount(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_IPlaybackPositionChangeRequestedEventArgs<D>::RequestedPlaybackPosition() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::IPlaybackPositionChangeRequestedEventArgs)->get_RequestedPlaybackPosition(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Media_IPlaybackRateChangeRequestedEventArgs<D>::RequestedPlaybackRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::IPlaybackRateChangeRequestedEventArgs)->get_RequestedPlaybackRate(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_IShuffleEnabledChangeRequestedEventArgs<D>::RequestedShuffleEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::IShuffleEnabledChangeRequestedEventArgs)->get_RequestedShuffleEnabled(&value));
    return value;
}

template <typename D> Windows::Media::MediaPlaybackStatus consume_Windows_Media_ISystemMediaTransportControls<D>::PlaybackStatus() const
{
    Windows::Media::MediaPlaybackStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_PlaybackStatus(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::PlaybackStatus(Windows::Media::MediaPlaybackStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_PlaybackStatus(get_abi(value)));
}

template <typename D> Windows::Media::SystemMediaTransportControlsDisplayUpdater consume_Windows_Media_ISystemMediaTransportControls<D>::DisplayUpdater() const
{
    Windows::Media::SystemMediaTransportControlsDisplayUpdater value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_DisplayUpdater(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SoundLevel consume_Windows_Media_ISystemMediaTransportControls<D>::SoundLevel() const
{
    Windows::Media::SoundLevel value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_SoundLevel(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsPlayEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsPlayEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsPlayEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsPlayEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsStopEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsStopEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsStopEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsStopEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsPauseEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsPauseEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsPauseEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsPauseEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsRecordEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsRecordEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsRecordEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsRecordEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsFastForwardEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsFastForwardEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsFastForwardEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsFastForwardEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsRewindEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsRewindEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsRewindEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsRewindEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsPreviousEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsPreviousEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsPreviousEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsPreviousEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsNextEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsNextEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsNextEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsNextEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelUpEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsChannelUpEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelUpEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsChannelUpEnabled(value));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelDownEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->get_IsChannelDownEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelDownEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->put_IsChannelDownEnabled(value));
}

template <typename D> winrt::event_token consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed(Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->add_ButtonPressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed_revoker consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ButtonPressed_revoker>(this, ButtonPressed(handler));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->remove_ButtonPressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged(Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->add_PropertyChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged_revoker consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PropertyChanged_revoker>(this, PropertyChanged(handler));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ISystemMediaTransportControls)->remove_PropertyChanged(get_abi(token)));
}

template <typename D> Windows::Media::MediaPlaybackAutoRepeatMode consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatMode() const
{
    Windows::Media::MediaPlaybackAutoRepeatMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->get_AutoRepeatMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatMode(Windows::Media::MediaPlaybackAutoRepeatMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->put_AutoRepeatMode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->get_ShuffleEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->put_ShuffleEnabled(value));
}

template <typename D> double consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->get_PlaybackRate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRate(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->put_PlaybackRate(value));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::UpdateTimelineProperties(Windows::Media::SystemMediaTransportControlsTimelineProperties const& timelineProperties) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->UpdateTimelineProperties(get_abi(timelineProperties)));
}

template <typename D> winrt::event_token consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackPositionChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->add_PlaybackPositionChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackPositionChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlaybackPositionChangeRequested_revoker>(this, PlaybackPositionChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->remove_PlaybackPositionChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackRateChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->add_PlaybackRateChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackRateChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlaybackRateChangeRequested_revoker>(this, PlaybackRateChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->remove_PlaybackRateChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->add_ShuffleEnabledChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ShuffleEnabledChangeRequested_revoker>(this, ShuffleEnabledChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->remove_ShuffleEnabledChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->add_AutoRepeatModeChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AutoRepeatModeChangeRequested_revoker>(this, AutoRepeatModeChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ISystemMediaTransportControls2)->remove_AutoRepeatModeChangeRequested(get_abi(token)));
}

template <typename D> Windows::Media::SystemMediaTransportControlsButton consume_Windows_Media_ISystemMediaTransportControlsButtonPressedEventArgs<D>::Button() const
{
    Windows::Media::SystemMediaTransportControlsButton value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs)->get_Button(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaPlaybackType consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Type() const
{
    Windows::Media::MediaPlaybackType value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Type(Windows::Media::MediaPlaybackType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->put_Type(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::AppMediaId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_AppMediaId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::AppMediaId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->put_AppMediaId(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Thumbnail() const
{
    Windows::Storage::Streams::RandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Thumbnail(Windows::Storage::Streams::RandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::Media::MusicDisplayProperties consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::MusicProperties() const
{
    Windows::Media::MusicDisplayProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_MusicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoDisplayProperties consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::VideoProperties() const
{
    Windows::Media::VideoDisplayProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_VideoProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ImageDisplayProperties consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::ImageProperties() const
{
    Windows::Media::ImageDisplayProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_ImageProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::CopyFromFileAsync(Windows::Media::MediaPlaybackType const& type, Windows::Storage::StorageFile const& source) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->CopyFromFileAsync(get_abi(type), get_abi(source), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::ClearAll() const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->ClearAll());
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Update() const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->Update());
}

template <typename D> Windows::Media::SystemMediaTransportControlsProperty consume_Windows_Media_ISystemMediaTransportControlsPropertyChangedEventArgs<D>::Property() const
{
    Windows::Media::SystemMediaTransportControlsProperty value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs)->get_Property(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::SystemMediaTransportControls consume_Windows_Media_ISystemMediaTransportControlsStatics<D>::GetForCurrentView() const
{
    Windows::Media::SystemMediaTransportControls mediaControl{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsStatics)->GetForCurrentView(put_abi(mediaControl)));
    return mediaControl;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::StartTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::StartTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_StartTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::EndTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_EndTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::EndTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_EndTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MinSeekTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_MinSeekTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MinSeekTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_MinSeekTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MaxSeekTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_MaxSeekTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MaxSeekTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_MaxSeekTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::Position() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::Position(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_Position(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IVideoDisplayProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IVideoDisplayProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IVideoDisplayProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IVideoDisplayProperties)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_IVideoDisplayProperties<D>::Subtitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IVideoDisplayProperties)->get_Subtitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_IVideoDisplayProperties<D>::Subtitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::IVideoDisplayProperties)->put_Subtitle(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Media_IVideoDisplayProperties2<D>::Genres() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoDisplayProperties2)->get_Genres(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_IVideoEffectsStatics<D>::VideoStabilization() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::IVideoEffectsStatics)->get_VideoStabilization(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Media_IVideoFrame<D>::SoftwareBitmap() const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrame)->get_SoftwareBitmap(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_IVideoFrame<D>::CopyToAsync(Windows::Media::VideoFrame const& frame) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrame)->CopyToAsync(get_abi(frame), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Media_IVideoFrame<D>::Direct3DSurface() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrame)->get_Direct3DSurface(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_IVideoFrame2<D>::CopyToAsync(Windows::Media::VideoFrame const& frame, optional<Windows::Graphics::Imaging::BitmapBounds> const& sourceBounds, optional<Windows::Graphics::Imaging::BitmapBounds> const& destinationBounds) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrame2)->CopyToWithBoundsAsync(get_abi(frame), get_abi(sourceBounds), get_abi(destinationBounds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_IVideoFrameFactory<D>::Create(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrameFactory)->Create(get_abi(format), width, height, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_IVideoFrameFactory<D>::CreateWithAlpha(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrameFactory)->CreateWithAlpha(get_abi(format), width, height, get_abi(alpha), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_IVideoFrameStatics<D>::CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height) const
{
    Windows::Media::VideoFrame result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrameStatics)->CreateAsDirect3D11SurfaceBacked(get_abi(format), width, height, put_abi(result)));
    return result;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_IVideoFrameStatics<D>::CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
{
    Windows::Media::VideoFrame result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrameStatics)->CreateAsDirect3D11SurfaceBackedWithDevice(get_abi(format), width, height, get_abi(device), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_IVideoFrameStatics<D>::CreateWithSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
{
    Windows::Media::VideoFrame result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrameStatics)->CreateWithSoftwareBitmap(get_abi(bitmap), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_IVideoFrameStatics<D>::CreateWithDirect3D11Surface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface) const
{
    Windows::Media::VideoFrame result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::IVideoFrameStatics)->CreateWithDirect3D11Surface(get_abi(surface), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Media::IAudioBuffer> : produce_base<D, Windows::Media::IAudioBuffer>
{
    int32_t WINRT_CALL get_Capacity(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capacity, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Length(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(void), uint32_t);
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IAudioFrame> : produce_base<D, Windows::Media::IAudioFrame>
{
    int32_t WINRT_CALL LockBuffer(Windows::Media::AudioBufferAccessMode mode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockBuffer, WINRT_WRAP(Windows::Media::AudioBuffer), Windows::Media::AudioBufferAccessMode const&);
            *value = detach_from<Windows::Media::AudioBuffer>(this->shim().LockBuffer(*reinterpret_cast<Windows::Media::AudioBufferAccessMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IAudioFrameFactory> : produce_base<D, Windows::Media::IAudioFrameFactory>
{
    int32_t WINRT_CALL Create(uint32_t capacity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::AudioFrame), uint32_t);
            *value = detach_from<Windows::Media::AudioFrame>(this->shim().Create(capacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IAutoRepeatModeChangeRequestedEventArgs> : produce_base<D, Windows::Media::IAutoRepeatModeChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_RequestedAutoRepeatMode(Windows::Media::MediaPlaybackAutoRepeatMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedAutoRepeatMode, WINRT_WRAP(Windows::Media::MediaPlaybackAutoRepeatMode));
            *value = detach_from<Windows::Media::MediaPlaybackAutoRepeatMode>(this->shim().RequestedAutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IImageDisplayProperties> : produce_base<D, Windows::Media::IImageDisplayProperties>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subtitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(void), hstring const&);
            this->shim().Subtitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaControl> : produce_base<D, Windows::Media::IMediaControl>
{
    int32_t WINRT_CALL add_SoundLevelChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoundLevelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().SoundLevelChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SoundLevelChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SoundLevelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SoundLevelChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PlayPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PlayPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlayPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlayPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlayPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PausePressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PausePressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PausePressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PausePressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PausePressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PausePressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StopPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StopPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StopPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StopPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StopPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PlayPauseTogglePressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayPauseTogglePressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PlayPauseTogglePressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlayPauseTogglePressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlayPauseTogglePressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlayPauseTogglePressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_RecordPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().RecordPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecordPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecordPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecordPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_NextTrackPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextTrackPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().NextTrackPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NextTrackPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NextTrackPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NextTrackPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PreviousTrackPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousTrackPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PreviousTrackPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PreviousTrackPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PreviousTrackPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PreviousTrackPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_FastForwardPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FastForwardPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().FastForwardPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FastForwardPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FastForwardPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FastForwardPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_RewindPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RewindPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().RewindPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RewindPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RewindPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RewindPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ChannelUpPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelUpPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ChannelUpPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ChannelUpPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ChannelUpPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ChannelUpPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ChannelDownPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelDownPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ChannelDownPressed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ChannelDownPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ChannelDownPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ChannelDownPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_SoundLevel(Windows::Media::SoundLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoundLevel, WINRT_WRAP(Windows::Media::SoundLevel));
            *value = detach_from<Windows::Media::SoundLevel>(this->shim().SoundLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrackName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackName, WINRT_WRAP(void), hstring const&);
            this->shim().TrackName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TrackName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ArtistName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArtistName, WINRT_WRAP(void), hstring const&);
            this->shim().ArtistName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ArtistName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArtistName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ArtistName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPlaying(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlaying, WINRT_WRAP(void), bool);
            this->shim().IsPlaying(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlaying(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlaying, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlaying());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlbumArt(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArt, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().AlbumArt(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlbumArt(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArt, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().AlbumArt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaExtension> : produce_base<D, Windows::Media::IMediaExtension>
{
    int32_t WINRT_CALL SetProperties(void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetProperties, WINRT_WRAP(void), Windows::Foundation::Collections::IPropertySet const&);
            this->shim().SetProperties(*reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaExtensionManager> : produce_base<D, Windows::Media::IMediaExtensionManager>
{
    int32_t WINRT_CALL RegisterSchemeHandler(void* activatableClassId, void* scheme) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterSchemeHandler, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().RegisterSchemeHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&scheme));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterSchemeHandlerWithSettings(void* activatableClassId, void* scheme, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterSchemeHandler, WINRT_WRAP(void), hstring const&, hstring const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().RegisterSchemeHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterByteStreamHandler(void* activatableClassId, void* fileExtension, void* mimeType) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterByteStreamHandler, WINRT_WRAP(void), hstring const&, hstring const&, hstring const&);
            this->shim().RegisterByteStreamHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&fileExtension), *reinterpret_cast<hstring const*>(&mimeType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterByteStreamHandlerWithSettings(void* activatableClassId, void* fileExtension, void* mimeType, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterByteStreamHandler, WINRT_WRAP(void), hstring const&, hstring const&, hstring const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().RegisterByteStreamHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&fileExtension), *reinterpret_cast<hstring const*>(&mimeType), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAudioDecoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAudioDecoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&);
            this->shim().RegisterAudioDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAudioDecoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAudioDecoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().RegisterAudioDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAudioEncoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAudioEncoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&);
            this->shim().RegisterAudioEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAudioEncoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAudioEncoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().RegisterAudioEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterVideoDecoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterVideoDecoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&);
            this->shim().RegisterVideoDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterVideoDecoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterVideoDecoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().RegisterVideoDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterVideoEncoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterVideoEncoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&);
            this->shim().RegisterVideoEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterVideoEncoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterVideoEncoder, WINRT_WRAP(void), hstring const&, winrt::guid const&, winrt::guid const&, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().RegisterVideoEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaExtensionManager2> : produce_base<D, Windows::Media::IMediaExtensionManager2>
{
    int32_t WINRT_CALL RegisterMediaExtensionForAppService(void* extension, void* connection) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterMediaExtensionForAppService, WINRT_WRAP(void), Windows::Media::IMediaExtension const&, Windows::ApplicationModel::AppService::AppServiceConnection const&);
            this->shim().RegisterMediaExtensionForAppService(*reinterpret_cast<Windows::Media::IMediaExtension const*>(&extension), *reinterpret_cast<Windows::ApplicationModel::AppService::AppServiceConnection const*>(&connection));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaFrame> : produce_base<D, Windows::Media::IMediaFrame>
{
    int32_t WINRT_CALL get_Type(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().RelativeTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().RelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemRelativeTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemRelativeTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().SystemRelativeTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemRelativeTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemRelativeTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().SystemRelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDiscontinuous(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDiscontinuous, WINRT_WRAP(void), bool);
            this->shim().IsDiscontinuous(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDiscontinuous(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDiscontinuous, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDiscontinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedProperties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaMarker> : produce_base<D, Windows::Media::IMediaMarker>
{
    int32_t WINRT_CALL get_Time(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Time, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Time());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaMarkerType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaMarkerType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MediaMarkerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaMarkerTypesStatics> : produce_base<D, Windows::Media::IMediaMarkerTypesStatics>
{
    int32_t WINRT_CALL get_Bookmark(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bookmark, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Bookmark());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaMarkers> : produce_base<D, Windows::Media::IMediaMarkers>
{
    int32_t WINRT_CALL get_Markers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Markers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::IMediaMarker>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::IMediaMarker>>(this->shim().Markers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaProcessingTriggerDetails> : produce_base<D, Windows::Media::IMediaProcessingTriggerDetails>
{
    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaTimelineController> : produce_base<D, Windows::Media::IMediaTimelineController>
{
    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
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

    int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClockRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClockRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ClockRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClockRate(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClockRate, WINRT_WRAP(void), double);
            this->shim().ClockRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Media::MediaTimelineControllerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::MediaTimelineControllerState));
            *value = detach_from<Windows::Media::MediaTimelineControllerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PositionChanged(void* positionChangedEventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const*>(&positionChangedEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PositionChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_StateChanged(void* stateChangedEventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const*>(&stateChangedEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaTimelineController2> : produce_base<D, Windows::Media::IMediaTimelineController2>
{
    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLoopingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLoopingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLoopingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLoopingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLoopingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsLoopingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Failed(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Failed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Media::MediaTimelineControllerFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Failed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Media::MediaTimelineControllerFailedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Failed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Failed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Failed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Ended(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ended, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Ended(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::MediaTimelineController, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Ended(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Ended, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Ended(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::IMediaTimelineControllerFailedEventArgs> : produce_base<D, Windows::Media::IMediaTimelineControllerFailedEventArgs>
{
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
struct produce<D, Windows::Media::IMusicDisplayProperties> : produce_base<D, Windows::Media::IMusicDisplayProperties>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlbumArtist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArtist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlbumArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlbumArtist(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArtist, WINRT_WRAP(void), hstring const&);
            this->shim().AlbumArtist(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Artist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Artist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Artist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Artist(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Artist, WINRT_WRAP(void), hstring const&);
            this->shim().Artist(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMusicDisplayProperties2> : produce_base<D, Windows::Media::IMusicDisplayProperties2>
{
    int32_t WINRT_CALL get_AlbumTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlbumTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlbumTitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTitle, WINRT_WRAP(void), hstring const&);
            this->shim().AlbumTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackNumber(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackNumber, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrackNumber(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackNumber, WINRT_WRAP(void), uint32_t);
            this->shim().TrackNumber(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Genres(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Genres, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Genres());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IMusicDisplayProperties3> : produce_base<D, Windows::Media::IMusicDisplayProperties3>
{
    int32_t WINRT_CALL get_AlbumTrackCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTrackCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AlbumTrackCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlbumTrackCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTrackCount, WINRT_WRAP(void), uint32_t);
            this->shim().AlbumTrackCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IPlaybackPositionChangeRequestedEventArgs> : produce_base<D, Windows::Media::IPlaybackPositionChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_RequestedPlaybackPosition(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedPlaybackPosition, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RequestedPlaybackPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IPlaybackRateChangeRequestedEventArgs> : produce_base<D, Windows::Media::IPlaybackRateChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_RequestedPlaybackRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedPlaybackRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RequestedPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IShuffleEnabledChangeRequestedEventArgs> : produce_base<D, Windows::Media::IShuffleEnabledChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_RequestedShuffleEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedShuffleEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RequestedShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControls> : produce_base<D, Windows::Media::ISystemMediaTransportControls>
{
    int32_t WINRT_CALL get_PlaybackStatus(Windows::Media::MediaPlaybackStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackStatus, WINRT_WRAP(Windows::Media::MediaPlaybackStatus));
            *value = detach_from<Windows::Media::MediaPlaybackStatus>(this->shim().PlaybackStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaybackStatus(Windows::Media::MediaPlaybackStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackStatus, WINRT_WRAP(void), Windows::Media::MediaPlaybackStatus const&);
            this->shim().PlaybackStatus(*reinterpret_cast<Windows::Media::MediaPlaybackStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayUpdater(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayUpdater, WINRT_WRAP(Windows::Media::SystemMediaTransportControlsDisplayUpdater));
            *value = detach_from<Windows::Media::SystemMediaTransportControlsDisplayUpdater>(this->shim().DisplayUpdater());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoundLevel(Windows::Media::SoundLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoundLevel, WINRT_WRAP(Windows::Media::SoundLevel));
            *value = detach_from<Windows::Media::SoundLevel>(this->shim().SoundLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_IsPlayEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlayEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPlayEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPlayEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStopEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStopEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStopEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsStopEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStopEnabled, WINRT_WRAP(void), bool);
            this->shim().IsStopEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPauseEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPauseEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPauseEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPauseEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPauseEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPauseEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRecordEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRecordEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRecordEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRecordEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRecordEnabled, WINRT_WRAP(void), bool);
            this->shim().IsRecordEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFastForwardEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFastForwardEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFastForwardEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsFastForwardEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFastForwardEnabled, WINRT_WRAP(void), bool);
            this->shim().IsFastForwardEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRewindEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRewindEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRewindEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRewindEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRewindEnabled, WINRT_WRAP(void), bool);
            this->shim().IsRewindEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPreviousEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPreviousEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPreviousEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPreviousEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPreviousEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPreviousEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNextEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNextEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNextEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsNextEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNextEnabled, WINRT_WRAP(void), bool);
            this->shim().IsNextEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsChannelUpEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelUpEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsChannelUpEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsChannelUpEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelUpEnabled, WINRT_WRAP(void), bool);
            this->shim().IsChannelUpEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsChannelDownEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelDownEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsChannelDownEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsChannelDownEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelDownEnabled, WINRT_WRAP(void), bool);
            this->shim().IsChannelDownEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ButtonPressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ButtonPressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ButtonPressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ButtonPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ButtonPressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PropertyChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PropertyChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PropertyChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PropertyChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PropertyChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PropertyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControls2> : produce_base<D, Windows::Media::ISystemMediaTransportControls2>
{
    int32_t WINRT_CALL get_AutoRepeatMode(Windows::Media::MediaPlaybackAutoRepeatMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatMode, WINRT_WRAP(Windows::Media::MediaPlaybackAutoRepeatMode));
            *value = detach_from<Windows::Media::MediaPlaybackAutoRepeatMode>(this->shim().AutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoRepeatMode(Windows::Media::MediaPlaybackAutoRepeatMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatMode, WINRT_WRAP(void), Windows::Media::MediaPlaybackAutoRepeatMode const&);
            this->shim().AutoRepeatMode(*reinterpret_cast<Windows::Media::MediaPlaybackAutoRepeatMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShuffleEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShuffleEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleEnabled, WINRT_WRAP(void), bool);
            this->shim().ShuffleEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaybackRate(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(void), double);
            this->shim().PlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateTimelineProperties(void* timelineProperties) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateTimelineProperties, WINRT_WRAP(void), Windows::Media::SystemMediaTransportControlsTimelineProperties const&);
            this->shim().UpdateTimelineProperties(*reinterpret_cast<Windows::Media::SystemMediaTransportControlsTimelineProperties const*>(&timelineProperties));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PlaybackPositionChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackPositionChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackPositionChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackPositionChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackPositionChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackPositionChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackPositionChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackPositionChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlaybackRateChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRateChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackRateChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackRateChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::PlaybackRateChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackRateChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackRateChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackRateChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ShuffleEnabledChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleEnabledChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ShuffleEnabledChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ShuffleEnabledChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ShuffleEnabledChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ShuffleEnabledChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AutoRepeatModeChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatModeChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AutoRepeatModeChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::SystemMediaTransportControls, Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AutoRepeatModeChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AutoRepeatModeChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AutoRepeatModeChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs> : produce_base<D, Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs>
{
    int32_t WINRT_CALL get_Button(Windows::Media::SystemMediaTransportControlsButton* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Button, WINRT_WRAP(Windows::Media::SystemMediaTransportControlsButton));
            *value = detach_from<Windows::Media::SystemMediaTransportControlsButton>(this->shim().Button());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControlsDisplayUpdater> : produce_base<D, Windows::Media::ISystemMediaTransportControlsDisplayUpdater>
{
    int32_t WINRT_CALL get_Type(Windows::Media::MediaPlaybackType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Media::MediaPlaybackType));
            *value = detach_from<Windows::Media::MediaPlaybackType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(Windows::Media::MediaPlaybackType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), Windows::Media::MediaPlaybackType const&);
            this->shim().Type(*reinterpret_cast<Windows::Media::MediaPlaybackType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppMediaId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMediaId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppMediaId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppMediaId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMediaId, WINRT_WRAP(void), hstring const&);
            this->shim().AppMediaId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::RandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MusicProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MusicProperties, WINRT_WRAP(Windows::Media::MusicDisplayProperties));
            *value = detach_from<Windows::Media::MusicDisplayProperties>(this->shim().MusicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoProperties, WINRT_WRAP(Windows::Media::VideoDisplayProperties));
            *value = detach_from<Windows::Media::VideoDisplayProperties>(this->shim().VideoProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageProperties, WINRT_WRAP(Windows::Media::ImageDisplayProperties));
            *value = detach_from<Windows::Media::ImageDisplayProperties>(this->shim().ImageProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyFromFileAsync(Windows::Media::MediaPlaybackType type, void* source, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyFromFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Media::MediaPlaybackType const, Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().CopyFromFileAsync(*reinterpret_cast<Windows::Media::MediaPlaybackType const*>(&type), *reinterpret_cast<Windows::Storage::StorageFile const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAll, WINRT_WRAP(void));
            this->shim().ClearAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Update() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void));
            this->shim().Update();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs> : produce_base<D, Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs>
{
    int32_t WINRT_CALL get_Property(Windows::Media::SystemMediaTransportControlsProperty* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Property, WINRT_WRAP(Windows::Media::SystemMediaTransportControlsProperty));
            *value = detach_from<Windows::Media::SystemMediaTransportControlsProperty>(this->shim().Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControlsStatics> : produce_base<D, Windows::Media::ISystemMediaTransportControlsStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** mediaControl) noexcept final
    {
        try
        {
            *mediaControl = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Media::SystemMediaTransportControls));
            *mediaControl = detach_from<Windows::Media::SystemMediaTransportControls>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ISystemMediaTransportControlsTimelineProperties> : produce_base<D, Windows::Media::ISystemMediaTransportControlsTimelineProperties>
{
    int32_t WINRT_CALL get_StartTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().StartTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().EndTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinSeekTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSeekTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MinSeekTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinSeekTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSeekTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().MinSeekTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSeekTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSeekTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MaxSeekTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxSeekTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSeekTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().MaxSeekTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoDisplayProperties> : produce_base<D, Windows::Media::IVideoDisplayProperties>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subtitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(void), hstring const&);
            this->shim().Subtitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoDisplayProperties2> : produce_base<D, Windows::Media::IVideoDisplayProperties2>
{
    int32_t WINRT_CALL get_Genres(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Genres, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Genres());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoEffectsStatics> : produce_base<D, Windows::Media::IVideoEffectsStatics>
{
    int32_t WINRT_CALL get_VideoStabilization(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoStabilization, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoStabilization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoFrame> : produce_base<D, Windows::Media::IVideoFrame>
{
    int32_t WINRT_CALL get_SoftwareBitmap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareBitmap, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap));
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().SoftwareBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyToAsync(void* frame, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyToAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::VideoFrame const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CopyToAsync(*reinterpret_cast<Windows::Media::VideoFrame const*>(&frame)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direct3DSurface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3DSurface, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3DSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoFrame2> : produce_base<D, Windows::Media::IVideoFrame2>
{
    int32_t WINRT_CALL CopyToWithBoundsAsync(void* frame, void* sourceBounds, void* destinationBounds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyToAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::VideoFrame const, Windows::Foundation::IReference<Windows::Graphics::Imaging::BitmapBounds> const, Windows::Foundation::IReference<Windows::Graphics::Imaging::BitmapBounds> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CopyToAsync(*reinterpret_cast<Windows::Media::VideoFrame const*>(&frame), *reinterpret_cast<Windows::Foundation::IReference<Windows::Graphics::Imaging::BitmapBounds> const*>(&sourceBounds), *reinterpret_cast<Windows::Foundation::IReference<Windows::Graphics::Imaging::BitmapBounds> const*>(&destinationBounds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoFrameFactory> : produce_base<D, Windows::Media::IVideoFrameFactory>
{
    int32_t WINRT_CALL Create(Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::VideoFrame), Windows::Graphics::Imaging::BitmapPixelFormat const&, int32_t, int32_t);
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().Create(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAlpha(Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAlpha, WINRT_WRAP(Windows::Media::VideoFrame), Windows::Graphics::Imaging::BitmapPixelFormat const&, int32_t, int32_t, Windows::Graphics::Imaging::BitmapAlphaMode const&);
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().CreateWithAlpha(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height, *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::IVideoFrameStatics> : produce_base<D, Windows::Media::IVideoFrameStatics>
{
    int32_t WINRT_CALL CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat format, int32_t width, int32_t height, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsDirect3D11SurfaceBacked, WINRT_WRAP(Windows::Media::VideoFrame), Windows::Graphics::DirectX::DirectXPixelFormat const&, int32_t, int32_t);
            *result = detach_from<Windows::Media::VideoFrame>(this->shim().CreateAsDirect3D11SurfaceBacked(*reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&format), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAsDirect3D11SurfaceBackedWithDevice(Windows::Graphics::DirectX::DirectXPixelFormat format, int32_t width, int32_t height, void* device, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsDirect3D11SurfaceBacked, WINRT_WRAP(Windows::Media::VideoFrame), Windows::Graphics::DirectX::DirectXPixelFormat const&, int32_t, int32_t, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&);
            *result = detach_from<Windows::Media::VideoFrame>(this->shim().CreateAsDirect3D11SurfaceBacked(*reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&format), width, height, *reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithSoftwareBitmap(void* bitmap, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSoftwareBitmap, WINRT_WRAP(Windows::Media::VideoFrame), Windows::Graphics::Imaging::SoftwareBitmap const&);
            *result = detach_from<Windows::Media::VideoFrame>(this->shim().CreateWithSoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithDirect3D11Surface(void* surface, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithDirect3D11Surface, WINRT_WRAP(Windows::Media::VideoFrame), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&);
            *result = detach_from<Windows::Media::VideoFrame>(this->shim().CreateWithDirect3D11Surface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media {

inline AudioFrame::AudioFrame(uint32_t capacity) :
    AudioFrame(impl::call_factory<AudioFrame, Windows::Media::IAudioFrameFactory>([&](auto&& f) { return f.Create(capacity); }))
{}

inline winrt::event_token MediaControl::SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.SoundLevelChanged(handler); });
}

inline MediaControl::SoundLevelChanged_revoker MediaControl::SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.SoundLevelChanged(handler) };
}

inline void MediaControl::SoundLevelChanged(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.SoundLevelChanged(cookie); });
}

inline winrt::event_token MediaControl::PlayPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PlayPressed(handler); });
}

inline MediaControl::PlayPressed_revoker MediaControl::PlayPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.PlayPressed(handler) };
}

inline void MediaControl::PlayPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PlayPressed(cookie); });
}

inline winrt::event_token MediaControl::PausePressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PausePressed(handler); });
}

inline MediaControl::PausePressed_revoker MediaControl::PausePressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.PausePressed(handler) };
}

inline void MediaControl::PausePressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PausePressed(cookie); });
}

inline winrt::event_token MediaControl::StopPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.StopPressed(handler); });
}

inline MediaControl::StopPressed_revoker MediaControl::StopPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.StopPressed(handler) };
}

inline void MediaControl::StopPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.StopPressed(cookie); });
}

inline winrt::event_token MediaControl::PlayPauseTogglePressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PlayPauseTogglePressed(handler); });
}

inline MediaControl::PlayPauseTogglePressed_revoker MediaControl::PlayPauseTogglePressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.PlayPauseTogglePressed(handler) };
}

inline void MediaControl::PlayPauseTogglePressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PlayPauseTogglePressed(cookie); });
}

inline winrt::event_token MediaControl::RecordPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.RecordPressed(handler); });
}

inline MediaControl::RecordPressed_revoker MediaControl::RecordPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.RecordPressed(handler) };
}

inline void MediaControl::RecordPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.RecordPressed(cookie); });
}

inline winrt::event_token MediaControl::NextTrackPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.NextTrackPressed(handler); });
}

inline MediaControl::NextTrackPressed_revoker MediaControl::NextTrackPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.NextTrackPressed(handler) };
}

inline void MediaControl::NextTrackPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.NextTrackPressed(cookie); });
}

inline winrt::event_token MediaControl::PreviousTrackPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PreviousTrackPressed(handler); });
}

inline MediaControl::PreviousTrackPressed_revoker MediaControl::PreviousTrackPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.PreviousTrackPressed(handler) };
}

inline void MediaControl::PreviousTrackPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.PreviousTrackPressed(cookie); });
}

inline winrt::event_token MediaControl::FastForwardPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.FastForwardPressed(handler); });
}

inline MediaControl::FastForwardPressed_revoker MediaControl::FastForwardPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.FastForwardPressed(handler) };
}

inline void MediaControl::FastForwardPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.FastForwardPressed(cookie); });
}

inline winrt::event_token MediaControl::RewindPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.RewindPressed(handler); });
}

inline MediaControl::RewindPressed_revoker MediaControl::RewindPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.RewindPressed(handler) };
}

inline void MediaControl::RewindPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.RewindPressed(cookie); });
}

inline winrt::event_token MediaControl::ChannelUpPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.ChannelUpPressed(handler); });
}

inline MediaControl::ChannelUpPressed_revoker MediaControl::ChannelUpPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.ChannelUpPressed(handler) };
}

inline void MediaControl::ChannelUpPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.ChannelUpPressed(cookie); });
}

inline winrt::event_token MediaControl::ChannelDownPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.ChannelDownPressed(handler); });
}

inline MediaControl::ChannelDownPressed_revoker MediaControl::ChannelDownPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MediaControl, Windows::Media::IMediaControl>();
    return { f, f.ChannelDownPressed(handler) };
}

inline void MediaControl::ChannelDownPressed(winrt::event_token const& cookie)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.ChannelDownPressed(cookie); });
}

inline Windows::Media::SoundLevel MediaControl::SoundLevel()
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.SoundLevel(); });
}

inline void MediaControl::TrackName(param::hstring const& value)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.TrackName(value); });
}

inline hstring MediaControl::TrackName()
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.TrackName(); });
}

inline void MediaControl::ArtistName(param::hstring const& value)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.ArtistName(value); });
}

inline hstring MediaControl::ArtistName()
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.ArtistName(); });
}

inline void MediaControl::IsPlaying(bool value)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.IsPlaying(value); });
}

inline bool MediaControl::IsPlaying()
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.IsPlaying(); });
}

inline void MediaControl::AlbumArt(Windows::Foundation::Uri const& value)
{
    impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.AlbumArt(value); });
}

inline Windows::Foundation::Uri MediaControl::AlbumArt()
{
    return impl::call_factory<MediaControl, Windows::Media::IMediaControl>([&](auto&& f) { return f.AlbumArt(); });
}

inline MediaExtensionManager::MediaExtensionManager() :
    MediaExtensionManager(impl::call_factory<MediaExtensionManager>([](auto&& f) { return f.template ActivateInstance<MediaExtensionManager>(); }))
{}

inline hstring MediaMarkerTypes::Bookmark()
{
    return impl::call_factory<MediaMarkerTypes, Windows::Media::IMediaMarkerTypesStatics>([&](auto&& f) { return f.Bookmark(); });
}

inline MediaTimelineController::MediaTimelineController() :
    MediaTimelineController(impl::call_factory<MediaTimelineController>([](auto&& f) { return f.template ActivateInstance<MediaTimelineController>(); }))
{}

inline Windows::Media::SystemMediaTransportControls SystemMediaTransportControls::GetForCurrentView()
{
    return impl::call_factory<SystemMediaTransportControls, Windows::Media::ISystemMediaTransportControlsStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline SystemMediaTransportControlsTimelineProperties::SystemMediaTransportControlsTimelineProperties() :
    SystemMediaTransportControlsTimelineProperties(impl::call_factory<SystemMediaTransportControlsTimelineProperties>([](auto&& f) { return f.template ActivateInstance<SystemMediaTransportControlsTimelineProperties>(); }))
{}

inline hstring VideoEffects::VideoStabilization()
{
    return impl::call_factory<VideoEffects, Windows::Media::IVideoEffectsStatics>([&](auto&& f) { return f.VideoStabilization(); });
}

inline VideoFrame::VideoFrame(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) :
    VideoFrame(impl::call_factory<VideoFrame, Windows::Media::IVideoFrameFactory>([&](auto&& f) { return f.Create(format, width, height); }))
{}

inline VideoFrame::VideoFrame(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) :
    VideoFrame(impl::call_factory<VideoFrame, Windows::Media::IVideoFrameFactory>([&](auto&& f) { return f.CreateWithAlpha(format, width, height, alpha); }))
{}

inline Windows::Media::VideoFrame VideoFrame::CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height)
{
    return impl::call_factory<VideoFrame, Windows::Media::IVideoFrameStatics>([&](auto&& f) { return f.CreateAsDirect3D11SurfaceBacked(format, width, height); });
}

inline Windows::Media::VideoFrame VideoFrame::CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device)
{
    return impl::call_factory<VideoFrame, Windows::Media::IVideoFrameStatics>([&](auto&& f) { return f.CreateAsDirect3D11SurfaceBacked(format, width, height, device); });
}

inline Windows::Media::VideoFrame VideoFrame::CreateWithSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap)
{
    return impl::call_factory<VideoFrame, Windows::Media::IVideoFrameStatics>([&](auto&& f) { return f.CreateWithSoftwareBitmap(bitmap); });
}

inline Windows::Media::VideoFrame VideoFrame::CreateWithDirect3D11Surface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface)
{
    return impl::call_factory<VideoFrame, Windows::Media::IVideoFrameStatics>([&](auto&& f) { return f.CreateWithDirect3D11Surface(surface); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::IAudioBuffer> : winrt::impl::hash_base<winrt::Windows::Media::IAudioBuffer> {};
template<> struct hash<winrt::Windows::Media::IAudioFrame> : winrt::impl::hash_base<winrt::Windows::Media::IAudioFrame> {};
template<> struct hash<winrt::Windows::Media::IAudioFrameFactory> : winrt::impl::hash_base<winrt::Windows::Media::IAudioFrameFactory> {};
template<> struct hash<winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::IImageDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::IImageDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::IMediaControl> : winrt::impl::hash_base<winrt::Windows::Media::IMediaControl> {};
template<> struct hash<winrt::Windows::Media::IMediaExtension> : winrt::impl::hash_base<winrt::Windows::Media::IMediaExtension> {};
template<> struct hash<winrt::Windows::Media::IMediaExtensionManager> : winrt::impl::hash_base<winrt::Windows::Media::IMediaExtensionManager> {};
template<> struct hash<winrt::Windows::Media::IMediaExtensionManager2> : winrt::impl::hash_base<winrt::Windows::Media::IMediaExtensionManager2> {};
template<> struct hash<winrt::Windows::Media::IMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::IMediaFrame> {};
template<> struct hash<winrt::Windows::Media::IMediaMarker> : winrt::impl::hash_base<winrt::Windows::Media::IMediaMarker> {};
template<> struct hash<winrt::Windows::Media::IMediaMarkerTypesStatics> : winrt::impl::hash_base<winrt::Windows::Media::IMediaMarkerTypesStatics> {};
template<> struct hash<winrt::Windows::Media::IMediaMarkers> : winrt::impl::hash_base<winrt::Windows::Media::IMediaMarkers> {};
template<> struct hash<winrt::Windows::Media::IMediaProcessingTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Media::IMediaProcessingTriggerDetails> {};
template<> struct hash<winrt::Windows::Media::IMediaTimelineController> : winrt::impl::hash_base<winrt::Windows::Media::IMediaTimelineController> {};
template<> struct hash<winrt::Windows::Media::IMediaTimelineController2> : winrt::impl::hash_base<winrt::Windows::Media::IMediaTimelineController2> {};
template<> struct hash<winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::IMusicDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::IMusicDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::IMusicDisplayProperties2> : winrt::impl::hash_base<winrt::Windows::Media::IMusicDisplayProperties2> {};
template<> struct hash<winrt::Windows::Media::IMusicDisplayProperties3> : winrt::impl::hash_base<winrt::Windows::Media::IMusicDisplayProperties3> {};
template<> struct hash<winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControls> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControls> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControls2> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControls2> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsStatics> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControlsStatics> {};
template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties> : winrt::impl::hash_base<winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties> {};
template<> struct hash<winrt::Windows::Media::IVideoDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::IVideoDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::IVideoDisplayProperties2> : winrt::impl::hash_base<winrt::Windows::Media::IVideoDisplayProperties2> {};
template<> struct hash<winrt::Windows::Media::IVideoEffectsStatics> : winrt::impl::hash_base<winrt::Windows::Media::IVideoEffectsStatics> {};
template<> struct hash<winrt::Windows::Media::IVideoFrame> : winrt::impl::hash_base<winrt::Windows::Media::IVideoFrame> {};
template<> struct hash<winrt::Windows::Media::IVideoFrame2> : winrt::impl::hash_base<winrt::Windows::Media::IVideoFrame2> {};
template<> struct hash<winrt::Windows::Media::IVideoFrameFactory> : winrt::impl::hash_base<winrt::Windows::Media::IVideoFrameFactory> {};
template<> struct hash<winrt::Windows::Media::IVideoFrameStatics> : winrt::impl::hash_base<winrt::Windows::Media::IVideoFrameStatics> {};
template<> struct hash<winrt::Windows::Media::AudioBuffer> : winrt::impl::hash_base<winrt::Windows::Media::AudioBuffer> {};
template<> struct hash<winrt::Windows::Media::AudioFrame> : winrt::impl::hash_base<winrt::Windows::Media::AudioFrame> {};
template<> struct hash<winrt::Windows::Media::AutoRepeatModeChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::AutoRepeatModeChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::ImageDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::ImageDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::MediaControl> : winrt::impl::hash_base<winrt::Windows::Media::MediaControl> {};
template<> struct hash<winrt::Windows::Media::MediaExtensionManager> : winrt::impl::hash_base<winrt::Windows::Media::MediaExtensionManager> {};
template<> struct hash<winrt::Windows::Media::MediaMarkerTypes> : winrt::impl::hash_base<winrt::Windows::Media::MediaMarkerTypes> {};
template<> struct hash<winrt::Windows::Media::MediaProcessingTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Media::MediaProcessingTriggerDetails> {};
template<> struct hash<winrt::Windows::Media::MediaTimelineController> : winrt::impl::hash_base<winrt::Windows::Media::MediaTimelineController> {};
template<> struct hash<winrt::Windows::Media::MediaTimelineControllerFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::MediaTimelineControllerFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::MusicDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::MusicDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::PlaybackPositionChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlaybackPositionChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlaybackRateChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::ShuffleEnabledChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::ShuffleEnabledChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SystemMediaTransportControls> : winrt::impl::hash_base<winrt::Windows::Media::SystemMediaTransportControls> {};
template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsDisplayUpdater> : winrt::impl::hash_base<winrt::Windows::Media::SystemMediaTransportControlsDisplayUpdater> {};
template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsTimelineProperties> : winrt::impl::hash_base<winrt::Windows::Media::SystemMediaTransportControlsTimelineProperties> {};
template<> struct hash<winrt::Windows::Media::VideoDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::VideoDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::VideoEffects> : winrt::impl::hash_base<winrt::Windows::Media::VideoEffects> {};
template<> struct hash<winrt::Windows::Media::VideoFrame> : winrt::impl::hash_base<winrt::Windows::Media::VideoFrame> {};

}
