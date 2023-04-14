// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Lights.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Lights.Effects.2.h"
#include "winrt/Windows.Devices.Lights.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::StartDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->get_StartDelay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::StartDelay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->put_StartDelay(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::UpdateInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->get_UpdateInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::UpdateInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->put_UpdateInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::SuggestedBitmapSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->get_SuggestedBitmapSize(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::BitmapRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayBitmapEffect, Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->add_BitmapRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::BitmapRequested_revoker consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::BitmapRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayBitmapEffect, Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BitmapRequested_revoker>(this, BitmapRequested(handler));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect<D>::BitmapRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffect)->remove_BitmapRequested(get_abi(token)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayBitmapEffect consume_Windows_Devices_Lights_Effects_ILampArrayBitmapEffectFactory<D>::CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const
{
    Windows::Devices::Lights::Effects::LampArrayBitmapEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory)->CreateInstance(get_abi(lampArray), lampIndexes.size(), get_abi(lampIndexes), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBitmapRequestedEventArgs<D>::SinceStarted() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs)->get_SinceStarted(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBitmapRequestedEventArgs<D>::UpdateBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs)->UpdateBitmap(get_abi(bitmap)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_Color(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::AttackDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_AttackDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::AttackDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_AttackDuration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::SustainDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_SustainDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::SustainDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_SustainDuration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::DecayDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_DecayDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::DecayDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_DecayDuration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::RepetitionDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_RepetitionDelay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::RepetitionDelay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_RepetitionDelay(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::StartDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_StartDelay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::StartDelay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_StartDelay(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::Occurrences() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_Occurrences(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::Occurrences(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_Occurrences(value));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayRepetitionMode consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::RepetitionMode() const
{
    Windows::Devices::Lights::Effects::LampArrayRepetitionMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->get_RepetitionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect<D>::RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffect)->put_RepetitionMode(get_abi(value)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayBlinkEffect consume_Windows_Devices_Lights_Effects_ILampArrayBlinkEffectFactory<D>::CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const
{
    Windows::Devices::Lights::Effects::LampArrayBlinkEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory)->CreateInstance(get_abi(lampArray), lampIndexes.size(), get_abi(lampIndexes), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->put_Color(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::RampDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->get_RampDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::RampDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->put_RampDuration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::StartDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->get_StartDelay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::StartDelay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->put_StartDelay(get_abi(value)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::CompletionBehavior() const
{
    Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->get_CompletionBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect<D>::CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffect)->put_CompletionBehavior(get_abi(value)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayColorRampEffect consume_Windows_Devices_Lights_Effects_ILampArrayColorRampEffectFactory<D>::CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const
{
    Windows::Devices::Lights::Effects::LampArrayColorRampEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory)->CreateInstance(get_abi(lampArray), lampIndexes.size(), get_abi(lampIndexes), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffect)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffect)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::UpdateInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffect)->get_UpdateInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::UpdateInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffect)->put_UpdateInterval(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::UpdateRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayCustomEffect, Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffect)->add_UpdateRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::UpdateRequested_revoker consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::UpdateRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayCustomEffect, Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UpdateRequested_revoker>(this, UpdateRequested(handler));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffect<D>::UpdateRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffect)->remove_UpdateRequested(get_abi(token)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayCustomEffect consume_Windows_Devices_Lights_Effects_ILampArrayCustomEffectFactory<D>::CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const
{
    Windows::Devices::Lights::Effects::LampArrayCustomEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory)->CreateInstance(get_abi(lampArray), lampIndexes.size(), get_abi(lampIndexes), put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_Effects_ILampArrayEffect<D>::ZIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffect)->get_ZIndex(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffect<D>::ZIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffect)->put_ZIndex(value));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::Append(Windows::Devices::Lights::Effects::ILampArrayEffect const& effect) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->Append(get_abi(effect)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::OverrideZIndex(int32_t zIndex) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->OverrideZIndex(zIndex));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->Start());
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->Stop());
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->Pause());
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayEffectStartMode consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::EffectStartMode() const
{
    Windows::Devices::Lights::Effects::LampArrayEffectStartMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->get_EffectStartMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::EffectStartMode(Windows::Devices::Lights::Effects::LampArrayEffectStartMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->put_EffectStartMode(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::Occurrences() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->get_Occurrences(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::Occurrences(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->put_Occurrences(value));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayRepetitionMode consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::RepetitionMode() const
{
    Windows::Devices::Lights::Effects::LampArrayRepetitionMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->get_RepetitionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist<D>::RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist)->put_RepetitionMode(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics<D>::StartAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics)->StartAll(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics<D>::StopAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics)->StopAll(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics<D>::PauseAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics)->PauseAll(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->put_Color(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::StartDelay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->get_StartDelay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::StartDelay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->put_StartDelay(get_abi(value)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::CompletionBehavior() const
{
    Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->get_CompletionBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArraySolidEffect<D>::CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffect)->put_CompletionBehavior(get_abi(value)));
}

template <typename D> Windows::Devices::Lights::Effects::LampArraySolidEffect consume_Windows_Devices_Lights_Effects_ILampArraySolidEffectFactory<D>::CreateInstance(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) const
{
    Windows::Devices::Lights::Effects::LampArraySolidEffect value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory)->CreateInstance(get_abi(lampArray), lampIndexes.size(), get_abi(lampIndexes), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs<D>::SinceStarted() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs)->get_SinceStarted(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs<D>::SetColor(Windows::UI::Color const& desiredColor) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs)->SetColor(get_abi(desiredColor)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs<D>::SetColorForIndex(int32_t lampIndex, Windows::UI::Color const& desiredColor) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs)->SetColorForIndex(lampIndex, get_abi(desiredColor)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs<D>::SetSingleColorForIndices(Windows::UI::Color const& desiredColor, array_view<int32_t const> lampIndexes) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs)->SetSingleColorForIndices(get_abi(desiredColor), lampIndexes.size(), get_abi(lampIndexes)));
}

template <typename D> void consume_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs<D>::SetColorsForIndices(array_view<Windows::UI::Color const> desiredColors, array_view<int32_t const> lampIndexes) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs)->SetColorsForIndices(desiredColors.size(), get_abi(desiredColors), lampIndexes.size(), get_abi(lampIndexes)));
}

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayBitmapEffect> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayBitmapEffect>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().StartDelay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UpdateInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UpdateInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().UpdateInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuggestedBitmapSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestedBitmapSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().SuggestedBitmapSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BitmapRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayBitmapEffect, Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BitmapRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayBitmapEffect, Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BitmapRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BitmapRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BitmapRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayBitmapEffect), Windows::Devices::Lights::LampArray const&, array_view<int32_t const>);
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayBitmapEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Devices::Lights::LampArray const*>(&lampArray), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs>
{
    int32_t WINRT_CALL get_SinceStarted(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SinceStarted, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SinceStarted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateBitmap(void* bitmap) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&);
            this->shim().UpdateBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayBlinkEffect> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayBlinkEffect>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttackDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttackDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().AttackDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AttackDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttackDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().AttackDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SustainDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SustainDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SustainDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SustainDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SustainDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().SustainDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecayDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecayDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DecayDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecayDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecayDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DecayDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RepetitionDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepetitionDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RepetitionDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RepetitionDelay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepetitionDelay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().RepetitionDelay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().StartDelay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Occurrences(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Occurrences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Occurrences(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(void), int32_t);
            this->shim().Occurrences(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepetitionMode, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayRepetitionMode));
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayRepetitionMode>(this->shim().RepetitionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepetitionMode, WINRT_WRAP(void), Windows::Devices::Lights::Effects::LampArrayRepetitionMode const&);
            this->shim().RepetitionMode(*reinterpret_cast<Windows::Devices::Lights::Effects::LampArrayRepetitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayBlinkEffect), Windows::Devices::Lights::LampArray const&, array_view<int32_t const>);
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayBlinkEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Devices::Lights::LampArray const*>(&lampArray), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayColorRampEffect> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayColorRampEffect>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RampDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RampDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RampDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RampDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RampDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().RampDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().StartDelay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletionBehavior, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior));
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior>(this->shim().CompletionBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletionBehavior, WINRT_WRAP(void), Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const&);
            this->shim().CompletionBehavior(*reinterpret_cast<Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayColorRampEffect), Windows::Devices::Lights::LampArray const&, array_view<int32_t const>);
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayColorRampEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Devices::Lights::LampArray const*>(&lampArray), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayCustomEffect> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayCustomEffect>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UpdateInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UpdateInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().UpdateInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_UpdateRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayCustomEffect, Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UpdateRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Effects::LampArrayCustomEffect, Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UpdateRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UpdateRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UpdateRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayCustomEffect), Windows::Devices::Lights::LampArray const&, array_view<int32_t const>);
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayCustomEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Devices::Lights::LampArray const*>(&lampArray), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayEffect> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayEffect>
{
    int32_t WINRT_CALL get_ZIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(void), int32_t);
            this->shim().ZIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist>
{
    int32_t WINRT_CALL Append(void* effect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Append, WINRT_WRAP(void), Windows::Devices::Lights::Effects::ILampArrayEffect const&);
            this->shim().Append(*reinterpret_cast<Windows::Devices::Lights::Effects::ILampArrayEffect const*>(&effect));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OverrideZIndex(int32_t zIndex) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverrideZIndex, WINRT_WRAP(void), int32_t);
            this->shim().OverrideZIndex(zIndex);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
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

    int32_t WINRT_CALL get_EffectStartMode(Windows::Devices::Lights::Effects::LampArrayEffectStartMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectStartMode, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayEffectStartMode));
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayEffectStartMode>(this->shim().EffectStartMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EffectStartMode(Windows::Devices::Lights::Effects::LampArrayEffectStartMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectStartMode, WINRT_WRAP(void), Windows::Devices::Lights::Effects::LampArrayEffectStartMode const&);
            this->shim().EffectStartMode(*reinterpret_cast<Windows::Devices::Lights::Effects::LampArrayEffectStartMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Occurrences(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Occurrences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Occurrences(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(void), int32_t);
            this->shim().Occurrences(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepetitionMode, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayRepetitionMode));
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayRepetitionMode>(this->shim().RepetitionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RepetitionMode(Windows::Devices::Lights::Effects::LampArrayRepetitionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepetitionMode, WINRT_WRAP(void), Windows::Devices::Lights::Effects::LampArrayRepetitionMode const&);
            this->shim().RepetitionMode(*reinterpret_cast<Windows::Devices::Lights::Effects::LampArrayRepetitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>
{
    int32_t WINRT_CALL StartAll(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAll, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const&);
            this->shim().StartAll(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAll(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAll, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const&);
            this->shim().StopAll(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseAll(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseAll, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const&);
            this->shim().PauseAll(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArraySolidEffect> : produce_base<D, Windows::Devices::Lights::Effects::ILampArraySolidEffect>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartDelay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartDelay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDelay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().StartDelay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletionBehavior, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior));
            *value = detach_from<Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior>(this->shim().CompletionBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompletionBehavior(Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletionBehavior, WINRT_WRAP(void), Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const&);
            this->shim().CompletionBehavior(*reinterpret_cast<Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory> : produce_base<D, Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory>
{
    int32_t WINRT_CALL CreateInstance(void* lampArray, uint32_t __lampIndexesSize, int32_t* lampIndexes, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Lights::Effects::LampArraySolidEffect), Windows::Devices::Lights::LampArray const&, array_view<int32_t const>);
            *value = detach_from<Windows::Devices::Lights::Effects::LampArraySolidEffect>(this->shim().CreateInstance(*reinterpret_cast<Windows::Devices::Lights::LampArray const*>(&lampArray), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs> : produce_base<D, Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs>
{
    int32_t WINRT_CALL get_SinceStarted(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SinceStarted, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SinceStarted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColor(struct struct_Windows_UI_Color desiredColor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().SetColor(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorForIndex(int32_t lampIndex, struct struct_Windows_UI_Color desiredColor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorForIndex, WINRT_WRAP(void), int32_t, Windows::UI::Color const&);
            this->shim().SetColorForIndex(lampIndex, *reinterpret_cast<Windows::UI::Color const*>(&desiredColor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSingleColorForIndices(struct struct_Windows_UI_Color desiredColor, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSingleColorForIndices, WINRT_WRAP(void), Windows::UI::Color const&, array_view<int32_t const>);
            this->shim().SetSingleColorForIndices(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorsForIndices(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorsForIndices, WINRT_WRAP(void), array_view<Windows::UI::Color const>, array_view<int32_t const>);
            this->shim().SetColorsForIndices(array_view<Windows::UI::Color const>(reinterpret_cast<Windows::UI::Color const *>(desiredColors), reinterpret_cast<Windows::UI::Color const *>(desiredColors) + __desiredColorsSize), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Lights::Effects {

inline LampArrayBitmapEffect::LampArrayBitmapEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) :
    LampArrayBitmapEffect(impl::call_factory<LampArrayBitmapEffect, Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory>([&](auto&& f) { return f.CreateInstance(lampArray, lampIndexes); }))
{}

inline LampArrayBlinkEffect::LampArrayBlinkEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) :
    LampArrayBlinkEffect(impl::call_factory<LampArrayBlinkEffect, Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory>([&](auto&& f) { return f.CreateInstance(lampArray, lampIndexes); }))
{}

inline LampArrayColorRampEffect::LampArrayColorRampEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) :
    LampArrayColorRampEffect(impl::call_factory<LampArrayColorRampEffect, Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory>([&](auto&& f) { return f.CreateInstance(lampArray, lampIndexes); }))
{}

inline LampArrayCustomEffect::LampArrayCustomEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) :
    LampArrayCustomEffect(impl::call_factory<LampArrayCustomEffect, Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory>([&](auto&& f) { return f.CreateInstance(lampArray, lampIndexes); }))
{}

inline LampArrayEffectPlaylist::LampArrayEffectPlaylist() :
    LampArrayEffectPlaylist(impl::call_factory<LampArrayEffectPlaylist>([](auto&& f) { return f.template ActivateInstance<LampArrayEffectPlaylist>(); }))
{}

inline void LampArrayEffectPlaylist::StartAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value)
{
    impl::call_factory<LampArrayEffectPlaylist, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>([&](auto&& f) { return f.StartAll(value); });
}

inline void LampArrayEffectPlaylist::StopAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value)
{
    impl::call_factory<LampArrayEffectPlaylist, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>([&](auto&& f) { return f.StopAll(value); });
}

inline void LampArrayEffectPlaylist::PauseAll(param::iterable<Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value)
{
    impl::call_factory<LampArrayEffectPlaylist, Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics>([&](auto&& f) { return f.PauseAll(value); });
}

inline LampArraySolidEffect::LampArraySolidEffect(Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes) :
    LampArraySolidEffect(impl::call_factory<LampArraySolidEffect, Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory>([&](auto&& f) { return f.CreateInstance(lampArray, lampIndexes); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayBlinkEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayBlinkEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayColorRampEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayColorRampEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayCustomEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayCustomEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArraySolidEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArraySolidEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayBitmapEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayBitmapEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayBlinkEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayBlinkEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayColorRampEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayColorRampEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayCustomEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayCustomEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArraySolidEffect> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArraySolidEffect> {};
template<> struct hash<winrt::Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs> {};

}
