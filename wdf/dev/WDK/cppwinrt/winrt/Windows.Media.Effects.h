// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Editing.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/impl/Windows.Media.Render.2.h"
#include "winrt/impl/Windows.Media.Transcoding.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioCaptureEffectsManager, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioCaptureEffectsManager)->add_AudioCaptureEffectsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged_revoker consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioCaptureEffectsManager, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AudioCaptureEffectsChanged_revoker>(this, AudioCaptureEffectsChanged(handler));
}

template <typename D> void consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Effects::IAudioCaptureEffectsManager)->remove_AudioCaptureEffectsChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect> consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::GetAudioCaptureEffects() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect> effects{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioCaptureEffectsManager)->GetAudioCaptureEffects(put_abi(effects)));
    return effects;
}

template <typename D> Windows::Media::Effects::AudioEffectType consume_Windows_Media_Effects_IAudioEffect<D>::AudioEffectType() const
{
    Windows::Media::Effects::AudioEffectType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffect)->get_AudioEffectType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Effects_IAudioEffectDefinition<D>::ActivatableClassId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectDefinition)->get_ActivatableClassId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Media_Effects_IAudioEffectDefinition<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectDefinition)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::AudioEffectDefinition consume_Windows_Media_Effects_IAudioEffectDefinitionFactory<D>::Create(param::hstring const& activatableClassId) const
{
    Windows::Media::Effects::AudioEffectDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectDefinitionFactory)->Create(get_abi(activatableClassId), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::AudioEffectDefinition consume_Windows_Media_Effects_IAudioEffectDefinitionFactory<D>::CreateWithProperties(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) const
{
    Windows::Media::Effects::AudioEffectDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectDefinitionFactory)->CreateWithProperties(get_abi(activatableClassId), get_abi(props), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::AudioRenderEffectsManager consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioRenderEffectsManager(param::hstring const& deviceId, Windows::Media::Render::AudioRenderCategory const& category) const
{
    Windows::Media::Effects::AudioRenderEffectsManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioRenderEffectsManager(get_abi(deviceId), get_abi(category), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::AudioRenderEffectsManager consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioRenderEffectsManager(param::hstring const& deviceId, Windows::Media::Render::AudioRenderCategory const& category, Windows::Media::AudioProcessing const& mode) const
{
    Windows::Media::Effects::AudioRenderEffectsManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioRenderEffectsManagerWithMode(get_abi(deviceId), get_abi(category), get_abi(mode), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::AudioCaptureEffectsManager consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, Windows::Media::Capture::MediaCategory const& category) const
{
    Windows::Media::Effects::AudioCaptureEffectsManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioCaptureEffectsManager(get_abi(deviceId), get_abi(category), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::AudioCaptureEffectsManager consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, Windows::Media::Capture::MediaCategory const& category, Windows::Media::AudioProcessing const& mode) const
{
    Windows::Media::Effects::AudioCaptureEffectsManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioCaptureEffectsManagerWithMode(get_abi(deviceId), get_abi(category), get_abi(mode), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioRenderEffectsManager, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioRenderEffectsManager)->add_AudioRenderEffectsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged_revoker consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioRenderEffectsManager, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AudioRenderEffectsChanged_revoker>(this, AudioRenderEffectsChanged(handler));
}

template <typename D> void consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Effects::IAudioRenderEffectsManager)->remove_AudioRenderEffectsChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect> consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::GetAudioRenderEffects() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect> effects{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioRenderEffectsManager)->GetAudioRenderEffects(put_abi(effects)));
    return effects;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>::EffectsProviderThumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioRenderEffectsManager2)->get_EffectsProviderThumbnail(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>::EffectsProviderSettingsLabel() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioRenderEffectsManager2)->get_EffectsProviderSettingsLabel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>::ShowSettingsUI() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IAudioRenderEffectsManager2)->ShowSettingsUI());
}

template <typename D> bool consume_Windows_Media_Effects_IBasicAudioEffect<D>::UseInputFrameForOutput() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicAudioEffect)->get_UseInputFrameForOutput(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::AudioEncodingProperties> consume_Windows_Media_Effects_IBasicAudioEffect<D>::SupportedEncodingProperties() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::AudioEncodingProperties> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicAudioEffect)->get_SupportedEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IBasicAudioEffect<D>::SetEncodingProperties(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicAudioEffect)->SetEncodingProperties(get_abi(encodingProperties)));
}

template <typename D> void consume_Windows_Media_Effects_IBasicAudioEffect<D>::ProcessFrame(Windows::Media::Effects::ProcessAudioFrameContext const& context) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicAudioEffect)->ProcessFrame(get_abi(context)));
}

template <typename D> void consume_Windows_Media_Effects_IBasicAudioEffect<D>::Close(Windows::Media::Effects::MediaEffectClosedReason const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicAudioEffect)->Close(get_abi(reason)));
}

template <typename D> void consume_Windows_Media_Effects_IBasicAudioEffect<D>::DiscardQueuedFrames() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicAudioEffect)->DiscardQueuedFrames());
}

template <typename D> bool consume_Windows_Media_Effects_IBasicVideoEffect<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->get_IsReadOnly(&value));
    return value;
}

template <typename D> Windows::Media::Effects::MediaMemoryTypes consume_Windows_Media_Effects_IBasicVideoEffect<D>::SupportedMemoryTypes() const
{
    Windows::Media::Effects::MediaMemoryTypes value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->get_SupportedMemoryTypes(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Effects_IBasicVideoEffect<D>::TimeIndependent() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->get_TimeIndependent(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::VideoEncodingProperties> consume_Windows_Media_Effects_IBasicVideoEffect<D>::SupportedEncodingProperties() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::VideoEncodingProperties> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->get_SupportedEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IBasicVideoEffect<D>::SetEncodingProperties(Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->SetEncodingProperties(get_abi(encodingProperties), get_abi(device)));
}

template <typename D> void consume_Windows_Media_Effects_IBasicVideoEffect<D>::ProcessFrame(Windows::Media::Effects::ProcessVideoFrameContext const& context) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->ProcessFrame(get_abi(context)));
}

template <typename D> void consume_Windows_Media_Effects_IBasicVideoEffect<D>::Close(Windows::Media::Effects::MediaEffectClosedReason const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->Close(get_abi(reason)));
}

template <typename D> void consume_Windows_Media_Effects_IBasicVideoEffect<D>::DiscardQueuedFrames() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IBasicVideoEffect)->DiscardQueuedFrames());
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface> consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::SurfacesToOverlay() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::ICompositeVideoFrameContext)->get_SurfacesToOverlay(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::BackgroundFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::ICompositeVideoFrameContext)->get_BackgroundFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::OutputFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::ICompositeVideoFrameContext)->get_OutputFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Editing::MediaOverlay consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::GetOverlayForSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surfaceToOverlay) const
{
    Windows::Media::Editing::MediaOverlay value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::ICompositeVideoFrameContext)->GetOverlayForSurface(get_abi(surfaceToOverlay), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::AudioFrame consume_Windows_Media_Effects_IProcessAudioFrameContext<D>::InputFrame() const
{
    Windows::Media::AudioFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IProcessAudioFrameContext)->get_InputFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::AudioFrame consume_Windows_Media_Effects_IProcessAudioFrameContext<D>::OutputFrame() const
{
    Windows::Media::AudioFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IProcessAudioFrameContext)->get_OutputFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Effects_IProcessVideoFrameContext<D>::InputFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IProcessVideoFrameContext)->get_InputFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Effects_IProcessVideoFrameContext<D>::OutputFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IProcessVideoFrameContext)->get_OutputFrame(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Effects_IVideoCompositor<D>::TimeIndependent() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositor)->get_TimeIndependent(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoCompositor<D>::SetEncodingProperties(Windows::Media::MediaProperties::VideoEncodingProperties const& backgroundProperties, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositor)->SetEncodingProperties(get_abi(backgroundProperties), get_abi(device)));
}

template <typename D> void consume_Windows_Media_Effects_IVideoCompositor<D>::CompositeFrame(Windows::Media::Effects::CompositeVideoFrameContext const& context) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositor)->CompositeFrame(get_abi(context)));
}

template <typename D> void consume_Windows_Media_Effects_IVideoCompositor<D>::Close(Windows::Media::Effects::MediaEffectClosedReason const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositor)->Close(get_abi(reason)));
}

template <typename D> void consume_Windows_Media_Effects_IVideoCompositor<D>::DiscardQueuedFrames() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositor)->DiscardQueuedFrames());
}

template <typename D> hstring consume_Windows_Media_Effects_IVideoCompositorDefinition<D>::ActivatableClassId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositorDefinition)->get_ActivatableClassId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Media_Effects_IVideoCompositorDefinition<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositorDefinition)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::VideoCompositorDefinition consume_Windows_Media_Effects_IVideoCompositorDefinitionFactory<D>::Create(param::hstring const& activatableClassId) const
{
    Windows::Media::Effects::VideoCompositorDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositorDefinitionFactory)->Create(get_abi(activatableClassId), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::VideoCompositorDefinition consume_Windows_Media_Effects_IVideoCompositorDefinitionFactory<D>::CreateWithProperties(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) const
{
    Windows::Media::Effects::VideoCompositorDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoCompositorDefinitionFactory)->CreateWithProperties(get_abi(activatableClassId), get_abi(props), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Effects_IVideoEffectDefinition<D>::ActivatableClassId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoEffectDefinition)->get_ActivatableClassId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Media_Effects_IVideoEffectDefinition<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoEffectDefinition)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::VideoEffectDefinition consume_Windows_Media_Effects_IVideoEffectDefinitionFactory<D>::Create(param::hstring const& activatableClassId) const
{
    Windows::Media::Effects::VideoEffectDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoEffectDefinitionFactory)->Create(get_abi(activatableClassId), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::VideoEffectDefinition consume_Windows_Media_Effects_IVideoEffectDefinitionFactory<D>::CreateWithProperties(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) const
{
    Windows::Media::Effects::VideoEffectDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoEffectDefinitionFactory)->CreateWithProperties(get_abi(activatableClassId), get_abi(props), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::PaddingColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->get_PaddingColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::PaddingColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->put_PaddingColor(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::OutputSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->get_OutputSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::OutputSize(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->put_OutputSize(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::CropRectangle() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->get_CropRectangle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::CropRectangle(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->put_CropRectangle(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::MediaRotation consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Rotation() const
{
    Windows::Media::MediaProperties::MediaRotation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->get_Rotation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Rotation(Windows::Media::MediaProperties::MediaRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->put_Rotation(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::MediaMirroringOptions consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Mirror() const
{
    Windows::Media::MediaProperties::MediaMirroringOptions value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->get_Mirror(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Mirror(Windows::Media::MediaProperties::MediaMirroringOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->put_Mirror(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::ProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->put_ProcessingAlgorithm(get_abi(value)));
}

template <typename D> Windows::Media::Transcoding::MediaVideoProcessingAlgorithm consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::ProcessingAlgorithm() const
{
    Windows::Media::Transcoding::MediaVideoProcessingAlgorithm value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition)->get_ProcessingAlgorithm(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::VideoTransformSphericalProjection consume_Windows_Media_Effects_IVideoTransformEffectDefinition2<D>::SphericalProjection() const
{
    Windows::Media::Effects::VideoTransformSphericalProjection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformEffectDefinition2)->get_SphericalProjection(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->put_IsEnabled(value));
}

template <typename D> Windows::Media::MediaProperties::SphericalVideoFrameFormat consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::FrameFormat() const
{
    Windows::Media::MediaProperties::SphericalVideoFrameFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->get_FrameFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->put_FrameFormat(get_abi(value)));
}

template <typename D> Windows::Media::Playback::SphericalVideoProjectionMode consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ProjectionMode() const
{
    Windows::Media::Playback::SphericalVideoProjectionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->get_ProjectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->put_ProjectionMode(get_abi(value)));
}

template <typename D> double consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::HorizontalFieldOfViewInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->get_HorizontalFieldOfViewInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::HorizontalFieldOfViewInDegrees(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->put_HorizontalFieldOfViewInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ViewOrientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->get_ViewOrientation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ViewOrientation(Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Effects::IVideoTransformSphericalProjection)->put_ViewOrientation(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioCaptureEffectsManager> : produce_base<D, Windows::Media::Effects::IAudioCaptureEffectsManager>
{
    int32_t WINRT_CALL add_AudioCaptureEffectsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioCaptureEffectsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioCaptureEffectsManager, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AudioCaptureEffectsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioCaptureEffectsManager, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AudioCaptureEffectsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AudioCaptureEffectsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AudioCaptureEffectsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetAudioCaptureEffects(void** effects) noexcept final
    {
        try
        {
            *effects = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioCaptureEffects, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect>));
            *effects = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect>>(this->shim().GetAudioCaptureEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioEffect> : produce_base<D, Windows::Media::Effects::IAudioEffect>
{
    int32_t WINRT_CALL get_AudioEffectType(Windows::Media::Effects::AudioEffectType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEffectType, WINRT_WRAP(Windows::Media::Effects::AudioEffectType));
            *value = detach_from<Windows::Media::Effects::AudioEffectType>(this->shim().AudioEffectType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioEffectDefinition> : produce_base<D, Windows::Media::Effects::IAudioEffectDefinition>
{
    int32_t WINRT_CALL get_ActivatableClassId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivatableClassId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ActivatableClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioEffectDefinitionFactory> : produce_base<D, Windows::Media::Effects::IAudioEffectDefinitionFactory>
{
    int32_t WINRT_CALL Create(void* activatableClassId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Effects::AudioEffectDefinition), hstring const&);
            *value = detach_from<Windows::Media::Effects::AudioEffectDefinition>(this->shim().Create(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProperties, WINRT_WRAP(Windows::Media::Effects::AudioEffectDefinition), hstring const&, Windows::Foundation::Collections::IPropertySet const&);
            *value = detach_from<Windows::Media::Effects::AudioEffectDefinition>(this->shim().CreateWithProperties(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioEffectsManagerStatics> : produce_base<D, Windows::Media::Effects::IAudioEffectsManagerStatics>
{
    int32_t WINRT_CALL CreateAudioRenderEffectsManager(void* deviceId, Windows::Media::Render::AudioRenderCategory category, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAudioRenderEffectsManager, WINRT_WRAP(Windows::Media::Effects::AudioRenderEffectsManager), hstring const&, Windows::Media::Render::AudioRenderCategory const&);
            *value = detach_from<Windows::Media::Effects::AudioRenderEffectsManager>(this->shim().CreateAudioRenderEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Media::Render::AudioRenderCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAudioRenderEffectsManagerWithMode(void* deviceId, Windows::Media::Render::AudioRenderCategory category, Windows::Media::AudioProcessing mode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAudioRenderEffectsManager, WINRT_WRAP(Windows::Media::Effects::AudioRenderEffectsManager), hstring const&, Windows::Media::Render::AudioRenderCategory const&, Windows::Media::AudioProcessing const&);
            *value = detach_from<Windows::Media::Effects::AudioRenderEffectsManager>(this->shim().CreateAudioRenderEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Media::Render::AudioRenderCategory const*>(&category), *reinterpret_cast<Windows::Media::AudioProcessing const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAudioCaptureEffectsManager(void* deviceId, Windows::Media::Capture::MediaCategory category, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAudioCaptureEffectsManager, WINRT_WRAP(Windows::Media::Effects::AudioCaptureEffectsManager), hstring const&, Windows::Media::Capture::MediaCategory const&);
            *value = detach_from<Windows::Media::Effects::AudioCaptureEffectsManager>(this->shim().CreateAudioCaptureEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Media::Capture::MediaCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAudioCaptureEffectsManagerWithMode(void* deviceId, Windows::Media::Capture::MediaCategory category, Windows::Media::AudioProcessing mode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAudioCaptureEffectsManager, WINRT_WRAP(Windows::Media::Effects::AudioCaptureEffectsManager), hstring const&, Windows::Media::Capture::MediaCategory const&, Windows::Media::AudioProcessing const&);
            *value = detach_from<Windows::Media::Effects::AudioCaptureEffectsManager>(this->shim().CreateAudioCaptureEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<Windows::Media::AudioProcessing const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioRenderEffectsManager> : produce_base<D, Windows::Media::Effects::IAudioRenderEffectsManager>
{
    int32_t WINRT_CALL add_AudioRenderEffectsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioRenderEffectsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioRenderEffectsManager, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AudioRenderEffectsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioRenderEffectsManager, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AudioRenderEffectsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AudioRenderEffectsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AudioRenderEffectsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetAudioRenderEffects(void** effects) noexcept final
    {
        try
        {
            *effects = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioRenderEffects, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect>));
            *effects = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect>>(this->shim().GetAudioRenderEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IAudioRenderEffectsManager2> : produce_base<D, Windows::Media::Effects::IAudioRenderEffectsManager2>
{
    int32_t WINRT_CALL get_EffectsProviderThumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectsProviderThumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().EffectsProviderThumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EffectsProviderSettingsLabel(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectsProviderSettingsLabel, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EffectsProviderSettingsLabel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowSettingsUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowSettingsUI, WINRT_WRAP(void));
            this->shim().ShowSettingsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IBasicAudioEffect> : produce_base<D, Windows::Media::Effects::IBasicAudioEffect>
{
    int32_t WINRT_CALL get_UseInputFrameForOutput(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseInputFrameForOutput, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().UseInputFrameForOutput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedEncodingProperties, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::AudioEncodingProperties>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::AudioEncodingProperties>>(this->shim().SupportedEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEncodingProperties(void* encodingProperties) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEncodingProperties, WINRT_WRAP(void), Windows::Media::MediaProperties::AudioEncodingProperties const&);
            this->shim().SetEncodingProperties(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessFrame(void* context) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessFrame, WINRT_WRAP(void), Windows::Media::Effects::ProcessAudioFrameContext const&);
            this->shim().ProcessFrame(*reinterpret_cast<Windows::Media::Effects::ProcessAudioFrameContext const*>(&context));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close(Windows::Media::Effects::MediaEffectClosedReason reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void), Windows::Media::Effects::MediaEffectClosedReason const&);
            this->shim().Close(*reinterpret_cast<Windows::Media::Effects::MediaEffectClosedReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DiscardQueuedFrames() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscardQueuedFrames, WINRT_WRAP(void));
            this->shim().DiscardQueuedFrames();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IBasicVideoEffect> : produce_base<D, Windows::Media::Effects::IBasicVideoEffect>
{
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

    int32_t WINRT_CALL get_SupportedMemoryTypes(Windows::Media::Effects::MediaMemoryTypes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedMemoryTypes, WINRT_WRAP(Windows::Media::Effects::MediaMemoryTypes));
            *value = detach_from<Windows::Media::Effects::MediaMemoryTypes>(this->shim().SupportedMemoryTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeIndependent(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeIndependent, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TimeIndependent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedEncodingProperties, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::VideoEncodingProperties>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::VideoEncodingProperties>>(this->shim().SupportedEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEncodingProperties(void* encodingProperties, void* device) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEncodingProperties, WINRT_WRAP(void), Windows::Media::MediaProperties::VideoEncodingProperties const&, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&);
            this->shim().SetEncodingProperties(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingProperties const*>(&encodingProperties), *reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessFrame(void* context) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessFrame, WINRT_WRAP(void), Windows::Media::Effects::ProcessVideoFrameContext const&);
            this->shim().ProcessFrame(*reinterpret_cast<Windows::Media::Effects::ProcessVideoFrameContext const*>(&context));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close(Windows::Media::Effects::MediaEffectClosedReason reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void), Windows::Media::Effects::MediaEffectClosedReason const&);
            this->shim().Close(*reinterpret_cast<Windows::Media::Effects::MediaEffectClosedReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DiscardQueuedFrames() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscardQueuedFrames, WINRT_WRAP(void));
            this->shim().DiscardQueuedFrames();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::ICompositeVideoFrameContext> : produce_base<D, Windows::Media::Effects::ICompositeVideoFrameContext>
{
    int32_t WINRT_CALL get_SurfacesToOverlay(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SurfacesToOverlay, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>>(this->shim().SurfacesToOverlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().BackgroundFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().OutputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOverlayForSurface(void* surfaceToOverlay, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOverlayForSurface, WINRT_WRAP(Windows::Media::Editing::MediaOverlay), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&);
            *value = detach_from<Windows::Media::Editing::MediaOverlay>(this->shim().GetOverlayForSurface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surfaceToOverlay)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IProcessAudioFrameContext> : produce_base<D, Windows::Media::Effects::IProcessAudioFrameContext>
{
    int32_t WINRT_CALL get_InputFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputFrame, WINRT_WRAP(Windows::Media::AudioFrame));
            *value = detach_from<Windows::Media::AudioFrame>(this->shim().InputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputFrame, WINRT_WRAP(Windows::Media::AudioFrame));
            *value = detach_from<Windows::Media::AudioFrame>(this->shim().OutputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IProcessVideoFrameContext> : produce_base<D, Windows::Media::Effects::IProcessVideoFrameContext>
{
    int32_t WINRT_CALL get_InputFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().InputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().OutputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoCompositor> : produce_base<D, Windows::Media::Effects::IVideoCompositor>
{
    int32_t WINRT_CALL get_TimeIndependent(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeIndependent, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TimeIndependent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEncodingProperties(void* backgroundProperties, void* device) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEncodingProperties, WINRT_WRAP(void), Windows::Media::MediaProperties::VideoEncodingProperties const&, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&);
            this->shim().SetEncodingProperties(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingProperties const*>(&backgroundProperties), *reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompositeFrame(void* context) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeFrame, WINRT_WRAP(void), Windows::Media::Effects::CompositeVideoFrameContext const&);
            this->shim().CompositeFrame(*reinterpret_cast<Windows::Media::Effects::CompositeVideoFrameContext const*>(&context));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close(Windows::Media::Effects::MediaEffectClosedReason reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void), Windows::Media::Effects::MediaEffectClosedReason const&);
            this->shim().Close(*reinterpret_cast<Windows::Media::Effects::MediaEffectClosedReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DiscardQueuedFrames() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscardQueuedFrames, WINRT_WRAP(void));
            this->shim().DiscardQueuedFrames();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoCompositorDefinition> : produce_base<D, Windows::Media::Effects::IVideoCompositorDefinition>
{
    int32_t WINRT_CALL get_ActivatableClassId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivatableClassId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ActivatableClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoCompositorDefinitionFactory> : produce_base<D, Windows::Media::Effects::IVideoCompositorDefinitionFactory>
{
    int32_t WINRT_CALL Create(void* activatableClassId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Effects::VideoCompositorDefinition), hstring const&);
            *value = detach_from<Windows::Media::Effects::VideoCompositorDefinition>(this->shim().Create(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProperties, WINRT_WRAP(Windows::Media::Effects::VideoCompositorDefinition), hstring const&, Windows::Foundation::Collections::IPropertySet const&);
            *value = detach_from<Windows::Media::Effects::VideoCompositorDefinition>(this->shim().CreateWithProperties(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoEffectDefinition> : produce_base<D, Windows::Media::Effects::IVideoEffectDefinition>
{
    int32_t WINRT_CALL get_ActivatableClassId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivatableClassId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ActivatableClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoEffectDefinitionFactory> : produce_base<D, Windows::Media::Effects::IVideoEffectDefinitionFactory>
{
    int32_t WINRT_CALL Create(void* activatableClassId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Effects::VideoEffectDefinition), hstring const&);
            *value = detach_from<Windows::Media::Effects::VideoEffectDefinition>(this->shim().Create(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProperties, WINRT_WRAP(Windows::Media::Effects::VideoEffectDefinition), hstring const&, Windows::Foundation::Collections::IPropertySet const&);
            *value = detach_from<Windows::Media::Effects::VideoEffectDefinition>(this->shim().CreateWithProperties(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoTransformEffectDefinition> : produce_base<D, Windows::Media::Effects::IVideoTransformEffectDefinition>
{
    int32_t WINRT_CALL get_PaddingColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaddingColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PaddingColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PaddingColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaddingColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().PaddingColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().OutputSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutputSize(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().OutputSize(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CropRectangle(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CropRectangle, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().CropRectangle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CropRectangle(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CropRectangle, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().CropRectangle(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(Windows::Media::MediaProperties::MediaRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(Windows::Media::MediaProperties::MediaRotation));
            *value = detach_from<Windows::Media::MediaProperties::MediaRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rotation(Windows::Media::MediaProperties::MediaRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(void), Windows::Media::MediaProperties::MediaRotation const&);
            this->shim().Rotation(*reinterpret_cast<Windows::Media::MediaProperties::MediaRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mirror(Windows::Media::MediaProperties::MediaMirroringOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mirror, WINRT_WRAP(Windows::Media::MediaProperties::MediaMirroringOptions));
            *value = detach_from<Windows::Media::MediaProperties::MediaMirroringOptions>(this->shim().Mirror());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mirror(Windows::Media::MediaProperties::MediaMirroringOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mirror, WINRT_WRAP(void), Windows::Media::MediaProperties::MediaMirroringOptions const&);
            this->shim().Mirror(*reinterpret_cast<Windows::Media::MediaProperties::MediaMirroringOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessingAlgorithm, WINRT_WRAP(void), Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const&);
            this->shim().ProcessingAlgorithm(*reinterpret_cast<Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessingAlgorithm, WINRT_WRAP(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm));
            *value = detach_from<Windows::Media::Transcoding::MediaVideoProcessingAlgorithm>(this->shim().ProcessingAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoTransformEffectDefinition2> : produce_base<D, Windows::Media::Effects::IVideoTransformEffectDefinition2>
{
    int32_t WINRT_CALL get_SphericalProjection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SphericalProjection, WINRT_WRAP(Windows::Media::Effects::VideoTransformSphericalProjection));
            *value = detach_from<Windows::Media::Effects::VideoTransformSphericalProjection>(this->shim().SphericalProjection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Effects::IVideoTransformSphericalProjection> : produce_base<D, Windows::Media::Effects::IVideoTransformSphericalProjection>
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

    int32_t WINRT_CALL get_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameFormat, WINRT_WRAP(Windows::Media::MediaProperties::SphericalVideoFrameFormat));
            *value = detach_from<Windows::Media::MediaProperties::SphericalVideoFrameFormat>(this->shim().FrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameFormat, WINRT_WRAP(void), Windows::Media::MediaProperties::SphericalVideoFrameFormat const&);
            this->shim().FrameFormat(*reinterpret_cast<Windows::Media::MediaProperties::SphericalVideoFrameFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMode, WINRT_WRAP(Windows::Media::Playback::SphericalVideoProjectionMode));
            *value = detach_from<Windows::Media::Playback::SphericalVideoProjectionMode>(this->shim().ProjectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMode, WINRT_WRAP(void), Windows::Media::Playback::SphericalVideoProjectionMode const&);
            this->shim().ProjectionMode(*reinterpret_cast<Windows::Media::Playback::SphericalVideoProjectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalFieldOfViewInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalFieldOfViewInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalFieldOfViewInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalFieldOfViewInDegrees(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalFieldOfViewInDegrees, WINRT_WRAP(void), double);
            this->shim().HorizontalFieldOfViewInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewOrientation(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewOrientation, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().ViewOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewOrientation(Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewOrientation, WINRT_WRAP(void), Windows::Foundation::Numerics::quaternion const&);
            this->shim().ViewOrientation(*reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Effects {

inline AudioEffectDefinition::AudioEffectDefinition(param::hstring const& activatableClassId) :
    AudioEffectDefinition(impl::call_factory<AudioEffectDefinition, Windows::Media::Effects::IAudioEffectDefinitionFactory>([&](auto&& f) { return f.Create(activatableClassId); }))
{}

inline AudioEffectDefinition::AudioEffectDefinition(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) :
    AudioEffectDefinition(impl::call_factory<AudioEffectDefinition, Windows::Media::Effects::IAudioEffectDefinitionFactory>([&](auto&& f) { return f.CreateWithProperties(activatableClassId, props); }))
{}

inline Windows::Media::Effects::AudioRenderEffectsManager AudioEffectsManager::CreateAudioRenderEffectsManager(param::hstring const& deviceId, Windows::Media::Render::AudioRenderCategory const& category)
{
    return impl::call_factory<AudioEffectsManager, Windows::Media::Effects::IAudioEffectsManagerStatics>([&](auto&& f) { return f.CreateAudioRenderEffectsManager(deviceId, category); });
}

inline Windows::Media::Effects::AudioRenderEffectsManager AudioEffectsManager::CreateAudioRenderEffectsManager(param::hstring const& deviceId, Windows::Media::Render::AudioRenderCategory const& category, Windows::Media::AudioProcessing const& mode)
{
    return impl::call_factory<AudioEffectsManager, Windows::Media::Effects::IAudioEffectsManagerStatics>([&](auto&& f) { return f.CreateAudioRenderEffectsManager(deviceId, category, mode); });
}

inline Windows::Media::Effects::AudioCaptureEffectsManager AudioEffectsManager::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, Windows::Media::Capture::MediaCategory const& category)
{
    return impl::call_factory<AudioEffectsManager, Windows::Media::Effects::IAudioEffectsManagerStatics>([&](auto&& f) { return f.CreateAudioCaptureEffectsManager(deviceId, category); });
}

inline Windows::Media::Effects::AudioCaptureEffectsManager AudioEffectsManager::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, Windows::Media::Capture::MediaCategory const& category, Windows::Media::AudioProcessing const& mode)
{
    return impl::call_factory<AudioEffectsManager, Windows::Media::Effects::IAudioEffectsManagerStatics>([&](auto&& f) { return f.CreateAudioCaptureEffectsManager(deviceId, category, mode); });
}

inline VideoCompositorDefinition::VideoCompositorDefinition(param::hstring const& activatableClassId) :
    VideoCompositorDefinition(impl::call_factory<VideoCompositorDefinition, Windows::Media::Effects::IVideoCompositorDefinitionFactory>([&](auto&& f) { return f.Create(activatableClassId); }))
{}

inline VideoCompositorDefinition::VideoCompositorDefinition(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) :
    VideoCompositorDefinition(impl::call_factory<VideoCompositorDefinition, Windows::Media::Effects::IVideoCompositorDefinitionFactory>([&](auto&& f) { return f.CreateWithProperties(activatableClassId, props); }))
{}

inline VideoEffectDefinition::VideoEffectDefinition(param::hstring const& activatableClassId) :
    VideoEffectDefinition(impl::call_factory<VideoEffectDefinition, Windows::Media::Effects::IVideoEffectDefinitionFactory>([&](auto&& f) { return f.Create(activatableClassId); }))
{}

inline VideoEffectDefinition::VideoEffectDefinition(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) :
    VideoEffectDefinition(impl::call_factory<VideoEffectDefinition, Windows::Media::Effects::IVideoEffectDefinitionFactory>([&](auto&& f) { return f.CreateWithProperties(activatableClassId, props); }))
{}

inline VideoTransformEffectDefinition::VideoTransformEffectDefinition() :
    VideoTransformEffectDefinition(impl::call_factory<VideoTransformEffectDefinition>([](auto&& f) { return f.template ActivateInstance<VideoTransformEffectDefinition>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Effects::IAudioCaptureEffectsManager> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioCaptureEffectsManager> {};
template<> struct hash<winrt::Windows::Media::Effects::IAudioEffect> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioEffect> {};
template<> struct hash<winrt::Windows::Media::Effects::IAudioEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory> {};
template<> struct hash<winrt::Windows::Media::Effects::IAudioEffectsManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioEffectsManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Effects::IAudioRenderEffectsManager> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioRenderEffectsManager> {};
template<> struct hash<winrt::Windows::Media::Effects::IAudioRenderEffectsManager2> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IAudioRenderEffectsManager2> {};
template<> struct hash<winrt::Windows::Media::Effects::IBasicAudioEffect> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IBasicAudioEffect> {};
template<> struct hash<winrt::Windows::Media::Effects::IBasicVideoEffect> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IBasicVideoEffect> {};
template<> struct hash<winrt::Windows::Media::Effects::ICompositeVideoFrameContext> : winrt::impl::hash_base<winrt::Windows::Media::Effects::ICompositeVideoFrameContext> {};
template<> struct hash<winrt::Windows::Media::Effects::IProcessAudioFrameContext> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IProcessAudioFrameContext> {};
template<> struct hash<winrt::Windows::Media::Effects::IProcessVideoFrameContext> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IProcessVideoFrameContext> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoCompositor> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoCompositor> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoCompositorDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoCompositorDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoTransformEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoTransformEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoTransformEffectDefinition2> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoTransformEffectDefinition2> {};
template<> struct hash<winrt::Windows::Media::Effects::IVideoTransformSphericalProjection> : winrt::impl::hash_base<winrt::Windows::Media::Effects::IVideoTransformSphericalProjection> {};
template<> struct hash<winrt::Windows::Media::Effects::AudioCaptureEffectsManager> : winrt::impl::hash_base<winrt::Windows::Media::Effects::AudioCaptureEffectsManager> {};
template<> struct hash<winrt::Windows::Media::Effects::AudioEffect> : winrt::impl::hash_base<winrt::Windows::Media::Effects::AudioEffect> {};
template<> struct hash<winrt::Windows::Media::Effects::AudioEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::AudioEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::AudioEffectsManager> : winrt::impl::hash_base<winrt::Windows::Media::Effects::AudioEffectsManager> {};
template<> struct hash<winrt::Windows::Media::Effects::AudioRenderEffectsManager> : winrt::impl::hash_base<winrt::Windows::Media::Effects::AudioRenderEffectsManager> {};
template<> struct hash<winrt::Windows::Media::Effects::CompositeVideoFrameContext> : winrt::impl::hash_base<winrt::Windows::Media::Effects::CompositeVideoFrameContext> {};
template<> struct hash<winrt::Windows::Media::Effects::ProcessAudioFrameContext> : winrt::impl::hash_base<winrt::Windows::Media::Effects::ProcessAudioFrameContext> {};
template<> struct hash<winrt::Windows::Media::Effects::ProcessVideoFrameContext> : winrt::impl::hash_base<winrt::Windows::Media::Effects::ProcessVideoFrameContext> {};
template<> struct hash<winrt::Windows::Media::Effects::VideoCompositorDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::VideoCompositorDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::VideoEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::VideoEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::VideoTransformEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Effects::VideoTransformEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Effects::VideoTransformSphericalProjection> : winrt::impl::hash_base<winrt::Windows::Media::Effects::VideoTransformSphericalProjection> {};

}
