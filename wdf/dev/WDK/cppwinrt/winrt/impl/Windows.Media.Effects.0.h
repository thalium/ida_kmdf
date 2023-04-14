// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct IDirect3DDevice;
struct IDirect3DSurface;

}

WINRT_EXPORT namespace winrt::Windows::Media {

enum class AudioProcessing;
struct AudioFrame;
struct VideoFrame;

}

WINRT_EXPORT namespace winrt::Windows::Media::Capture {

enum class MediaCategory;

}

WINRT_EXPORT namespace winrt::Windows::Media::Editing {

struct MediaOverlay;

}

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

enum class MediaMirroringOptions : unsigned;
enum class MediaRotation;
enum class SphericalVideoFrameFormat;
struct AudioEncodingProperties;
struct VideoEncodingProperties;

}

WINRT_EXPORT namespace winrt::Windows::Media::Playback {

enum class SphericalVideoProjectionMode;

}

WINRT_EXPORT namespace winrt::Windows::Media::Render {

enum class AudioRenderCategory;

}

WINRT_EXPORT namespace winrt::Windows::Media::Transcoding {

enum class MediaVideoProcessingAlgorithm;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::Media::Effects {

enum class AudioEffectType : int32_t
{
    Other = 0,
    AcousticEchoCancellation = 1,
    NoiseSuppression = 2,
    AutomaticGainControl = 3,
    BeamForming = 4,
    ConstantToneRemoval = 5,
    Equalizer = 6,
    LoudnessEqualizer = 7,
    BassBoost = 8,
    VirtualSurround = 9,
    VirtualHeadphones = 10,
    SpeakerFill = 11,
    RoomCorrection = 12,
    BassManagement = 13,
    EnvironmentalEffects = 14,
    SpeakerProtection = 15,
    SpeakerCompensation = 16,
    DynamicRangeCompression = 17,
};

enum class MediaEffectClosedReason : int32_t
{
    Done = 0,
    UnknownError = 1,
    UnsupportedEncodingFormat = 2,
    EffectCurrentlyUnloaded = 3,
};

enum class MediaMemoryTypes : int32_t
{
    Gpu = 0,
    Cpu = 1,
    GpuAndCpu = 2,
};

struct IAudioCaptureEffectsManager;
struct IAudioEffect;
struct IAudioEffectDefinition;
struct IAudioEffectDefinitionFactory;
struct IAudioEffectsManagerStatics;
struct IAudioRenderEffectsManager;
struct IAudioRenderEffectsManager2;
struct IBasicAudioEffect;
struct IBasicVideoEffect;
struct ICompositeVideoFrameContext;
struct IProcessAudioFrameContext;
struct IProcessVideoFrameContext;
struct IVideoCompositor;
struct IVideoCompositorDefinition;
struct IVideoCompositorDefinitionFactory;
struct IVideoEffectDefinition;
struct IVideoEffectDefinitionFactory;
struct IVideoTransformEffectDefinition;
struct IVideoTransformEffectDefinition2;
struct IVideoTransformSphericalProjection;
struct AudioCaptureEffectsManager;
struct AudioEffect;
struct AudioEffectDefinition;
struct AudioEffectsManager;
struct AudioRenderEffectsManager;
struct CompositeVideoFrameContext;
struct ProcessAudioFrameContext;
struct ProcessVideoFrameContext;
struct VideoCompositorDefinition;
struct VideoEffectDefinition;
struct VideoTransformEffectDefinition;
struct VideoTransformSphericalProjection;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Effects::IAudioCaptureEffectsManager>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IAudioEffect>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IAudioEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IAudioEffectDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IAudioEffectsManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IAudioRenderEffectsManager>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IAudioRenderEffectsManager2>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IBasicAudioEffect>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IBasicVideoEffect>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::ICompositeVideoFrameContext>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IProcessAudioFrameContext>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IProcessVideoFrameContext>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoCompositor>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoCompositorDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoCompositorDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoEffectDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoTransformEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoTransformEffectDefinition2>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::IVideoTransformSphericalProjection>{ using type = interface_category; };
template <> struct category<Windows::Media::Effects::AudioCaptureEffectsManager>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::AudioEffect>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::AudioEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::AudioEffectsManager>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::AudioRenderEffectsManager>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::CompositeVideoFrameContext>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::ProcessAudioFrameContext>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::ProcessVideoFrameContext>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::VideoCompositorDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::VideoEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::VideoTransformEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::VideoTransformSphericalProjection>{ using type = class_category; };
template <> struct category<Windows::Media::Effects::AudioEffectType>{ using type = enum_category; };
template <> struct category<Windows::Media::Effects::MediaEffectClosedReason>{ using type = enum_category; };
template <> struct category<Windows::Media::Effects::MediaMemoryTypes>{ using type = enum_category; };
template <> struct name<Windows::Media::Effects::IAudioCaptureEffectsManager>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioCaptureEffectsManager" }; };
template <> struct name<Windows::Media::Effects::IAudioEffect>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioEffect" }; };
template <> struct name<Windows::Media::Effects::IAudioEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioEffectDefinition" }; };
template <> struct name<Windows::Media::Effects::IAudioEffectDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioEffectDefinitionFactory" }; };
template <> struct name<Windows::Media::Effects::IAudioEffectsManagerStatics>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioEffectsManagerStatics" }; };
template <> struct name<Windows::Media::Effects::IAudioRenderEffectsManager>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioRenderEffectsManager" }; };
template <> struct name<Windows::Media::Effects::IAudioRenderEffectsManager2>{ static constexpr auto & value{ L"Windows.Media.Effects.IAudioRenderEffectsManager2" }; };
template <> struct name<Windows::Media::Effects::IBasicAudioEffect>{ static constexpr auto & value{ L"Windows.Media.Effects.IBasicAudioEffect" }; };
template <> struct name<Windows::Media::Effects::IBasicVideoEffect>{ static constexpr auto & value{ L"Windows.Media.Effects.IBasicVideoEffect" }; };
template <> struct name<Windows::Media::Effects::ICompositeVideoFrameContext>{ static constexpr auto & value{ L"Windows.Media.Effects.ICompositeVideoFrameContext" }; };
template <> struct name<Windows::Media::Effects::IProcessAudioFrameContext>{ static constexpr auto & value{ L"Windows.Media.Effects.IProcessAudioFrameContext" }; };
template <> struct name<Windows::Media::Effects::IProcessVideoFrameContext>{ static constexpr auto & value{ L"Windows.Media.Effects.IProcessVideoFrameContext" }; };
template <> struct name<Windows::Media::Effects::IVideoCompositor>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoCompositor" }; };
template <> struct name<Windows::Media::Effects::IVideoCompositorDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoCompositorDefinition" }; };
template <> struct name<Windows::Media::Effects::IVideoCompositorDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoCompositorDefinitionFactory" }; };
template <> struct name<Windows::Media::Effects::IVideoEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoEffectDefinition" }; };
template <> struct name<Windows::Media::Effects::IVideoEffectDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoEffectDefinitionFactory" }; };
template <> struct name<Windows::Media::Effects::IVideoTransformEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoTransformEffectDefinition" }; };
template <> struct name<Windows::Media::Effects::IVideoTransformEffectDefinition2>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoTransformEffectDefinition2" }; };
template <> struct name<Windows::Media::Effects::IVideoTransformSphericalProjection>{ static constexpr auto & value{ L"Windows.Media.Effects.IVideoTransformSphericalProjection" }; };
template <> struct name<Windows::Media::Effects::AudioCaptureEffectsManager>{ static constexpr auto & value{ L"Windows.Media.Effects.AudioCaptureEffectsManager" }; };
template <> struct name<Windows::Media::Effects::AudioEffect>{ static constexpr auto & value{ L"Windows.Media.Effects.AudioEffect" }; };
template <> struct name<Windows::Media::Effects::AudioEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.AudioEffectDefinition" }; };
template <> struct name<Windows::Media::Effects::AudioEffectsManager>{ static constexpr auto & value{ L"Windows.Media.Effects.AudioEffectsManager" }; };
template <> struct name<Windows::Media::Effects::AudioRenderEffectsManager>{ static constexpr auto & value{ L"Windows.Media.Effects.AudioRenderEffectsManager" }; };
template <> struct name<Windows::Media::Effects::CompositeVideoFrameContext>{ static constexpr auto & value{ L"Windows.Media.Effects.CompositeVideoFrameContext" }; };
template <> struct name<Windows::Media::Effects::ProcessAudioFrameContext>{ static constexpr auto & value{ L"Windows.Media.Effects.ProcessAudioFrameContext" }; };
template <> struct name<Windows::Media::Effects::ProcessVideoFrameContext>{ static constexpr auto & value{ L"Windows.Media.Effects.ProcessVideoFrameContext" }; };
template <> struct name<Windows::Media::Effects::VideoCompositorDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.VideoCompositorDefinition" }; };
template <> struct name<Windows::Media::Effects::VideoEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.VideoEffectDefinition" }; };
template <> struct name<Windows::Media::Effects::VideoTransformEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Effects.VideoTransformEffectDefinition" }; };
template <> struct name<Windows::Media::Effects::VideoTransformSphericalProjection>{ static constexpr auto & value{ L"Windows.Media.Effects.VideoTransformSphericalProjection" }; };
template <> struct name<Windows::Media::Effects::AudioEffectType>{ static constexpr auto & value{ L"Windows.Media.Effects.AudioEffectType" }; };
template <> struct name<Windows::Media::Effects::MediaEffectClosedReason>{ static constexpr auto & value{ L"Windows.Media.Effects.MediaEffectClosedReason" }; };
template <> struct name<Windows::Media::Effects::MediaMemoryTypes>{ static constexpr auto & value{ L"Windows.Media.Effects.MediaMemoryTypes" }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioCaptureEffectsManager>{ static constexpr guid value{ 0x8F85C271,0x038D,0x4393,{ 0x82,0x98,0x54,0x01,0x10,0x60,0x8E,0xEF } }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioEffect>{ static constexpr guid value{ 0x34AAFA51,0x9207,0x4055,{ 0xBE,0x93,0x6E,0x57,0x34,0xA8,0x6A,0xE4 } }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioEffectDefinition>{ static constexpr guid value{ 0xE4D7F974,0x7D80,0x4F73,{ 0x90,0x89,0xE3,0x1C,0x9D,0xB9,0xC2,0x94 } }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioEffectDefinitionFactory>{ static constexpr guid value{ 0x8E1DA646,0xE705,0x45ED,{ 0x8A,0x2B,0xFC,0x4E,0x4F,0x40,0x5A,0x97 } }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioEffectsManagerStatics>{ static constexpr guid value{ 0x66406C04,0x86FA,0x47CC,{ 0xA3,0x15,0xF4,0x89,0xD8,0xC3,0xFE,0x10 } }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioRenderEffectsManager>{ static constexpr guid value{ 0x4DC98966,0x8751,0x42B2,{ 0xBF,0xCB,0x39,0xCA,0x78,0x64,0xBD,0x47 } }; };
template <> struct guid_storage<Windows::Media::Effects::IAudioRenderEffectsManager2>{ static constexpr guid value{ 0xA844CD09,0x5ECC,0x44B3,{ 0xBB,0x4E,0x1D,0xB0,0x72,0x87,0x13,0x9C } }; };
template <> struct guid_storage<Windows::Media::Effects::IBasicAudioEffect>{ static constexpr guid value{ 0x8C062C53,0x6BC0,0x48B8,{ 0xA9,0x9A,0x4B,0x41,0x55,0x0F,0x13,0x59 } }; };
template <> struct guid_storage<Windows::Media::Effects::IBasicVideoEffect>{ static constexpr guid value{ 0x8262C7EF,0xB360,0x40BE,{ 0x94,0x9B,0x2F,0xF4,0x2F,0xF3,0x56,0x93 } }; };
template <> struct guid_storage<Windows::Media::Effects::ICompositeVideoFrameContext>{ static constexpr guid value{ 0x6C30024B,0xF514,0x4278,{ 0xA5,0xF7,0xB9,0x18,0x80,0x49,0xD1,0x10 } }; };
template <> struct guid_storage<Windows::Media::Effects::IProcessAudioFrameContext>{ static constexpr guid value{ 0x4CD92946,0x1222,0x4A27,{ 0xA5,0x86,0xFB,0x3E,0x20,0x27,0x32,0x55 } }; };
template <> struct guid_storage<Windows::Media::Effects::IProcessVideoFrameContext>{ static constexpr guid value{ 0x276F0E2B,0x6461,0x401E,{ 0xBA,0x78,0x0F,0xDA,0xD6,0x11,0x4E,0xEC } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoCompositor>{ static constexpr guid value{ 0x8510B43E,0x420C,0x420F,{ 0x96,0xC7,0x7C,0x98,0xBB,0xA1,0xFC,0x55 } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoCompositorDefinition>{ static constexpr guid value{ 0x7946B8D0,0x2010,0x4AE3,{ 0x9A,0xB2,0x2C,0xEF,0x42,0xED,0xD4,0xD2 } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoCompositorDefinitionFactory>{ static constexpr guid value{ 0x4366FD10,0x68B8,0x4D52,{ 0x89,0xB6,0x02,0xA9,0x68,0xCC,0xA8,0x99 } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoEffectDefinition>{ static constexpr guid value{ 0x39F38CF0,0x8D0F,0x4F3E,{ 0x84,0xFC,0x2D,0x46,0xA5,0x29,0x79,0x43 } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoEffectDefinitionFactory>{ static constexpr guid value{ 0x81439B4E,0x6E33,0x428F,{ 0x9D,0x21,0xB5,0xAA,0xFE,0xF7,0x61,0x7C } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoTransformEffectDefinition>{ static constexpr guid value{ 0x9664BB6A,0x1EA6,0x4AA6,{ 0x80,0x74,0xAB,0xE8,0x85,0x1E,0xCA,0xE2 } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoTransformEffectDefinition2>{ static constexpr guid value{ 0xF0A8089F,0x66C8,0x4694,{ 0x9F,0xD9,0x11,0x36,0xAB,0xF7,0x44,0x4A } }; };
template <> struct guid_storage<Windows::Media::Effects::IVideoTransformSphericalProjection>{ static constexpr guid value{ 0xCF4401F0,0x9BF2,0x4C39,{ 0x9F,0x41,0xE0,0x22,0x51,0x4A,0x84,0x68 } }; };
template <> struct default_interface<Windows::Media::Effects::AudioCaptureEffectsManager>{ using type = Windows::Media::Effects::IAudioCaptureEffectsManager; };
template <> struct default_interface<Windows::Media::Effects::AudioEffect>{ using type = Windows::Media::Effects::IAudioEffect; };
template <> struct default_interface<Windows::Media::Effects::AudioEffectDefinition>{ using type = Windows::Media::Effects::IAudioEffectDefinition; };
template <> struct default_interface<Windows::Media::Effects::AudioRenderEffectsManager>{ using type = Windows::Media::Effects::IAudioRenderEffectsManager; };
template <> struct default_interface<Windows::Media::Effects::CompositeVideoFrameContext>{ using type = Windows::Media::Effects::ICompositeVideoFrameContext; };
template <> struct default_interface<Windows::Media::Effects::ProcessAudioFrameContext>{ using type = Windows::Media::Effects::IProcessAudioFrameContext; };
template <> struct default_interface<Windows::Media::Effects::ProcessVideoFrameContext>{ using type = Windows::Media::Effects::IProcessVideoFrameContext; };
template <> struct default_interface<Windows::Media::Effects::VideoCompositorDefinition>{ using type = Windows::Media::Effects::IVideoCompositorDefinition; };
template <> struct default_interface<Windows::Media::Effects::VideoEffectDefinition>{ using type = Windows::Media::Effects::IVideoEffectDefinition; };
template <> struct default_interface<Windows::Media::Effects::VideoTransformEffectDefinition>{ using type = Windows::Media::Effects::IVideoEffectDefinition; };
template <> struct default_interface<Windows::Media::Effects::VideoTransformSphericalProjection>{ using type = Windows::Media::Effects::IVideoTransformSphericalProjection; };

template <> struct abi<Windows::Media::Effects::IAudioCaptureEffectsManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_AudioCaptureEffectsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AudioCaptureEffectsChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioCaptureEffects(void** effects) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IAudioEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AudioEffectType(Windows::Media::Effects::AudioEffectType* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IAudioEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivatableClassId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IAudioEffectDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* activatableClassId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IAudioEffectsManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAudioRenderEffectsManager(void* deviceId, Windows::Media::Render::AudioRenderCategory category, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAudioRenderEffectsManagerWithMode(void* deviceId, Windows::Media::Render::AudioRenderCategory category, Windows::Media::AudioProcessing mode, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAudioCaptureEffectsManager(void* deviceId, Windows::Media::Capture::MediaCategory category, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAudioCaptureEffectsManagerWithMode(void* deviceId, Windows::Media::Capture::MediaCategory category, Windows::Media::AudioProcessing mode, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IAudioRenderEffectsManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_AudioRenderEffectsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AudioRenderEffectsChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioRenderEffects(void** effects) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IAudioRenderEffectsManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EffectsProviderThumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EffectsProviderSettingsLabel(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ShowSettingsUI() noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IBasicAudioEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UseInputFrameForOutput(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedEncodingProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetEncodingProperties(void* encodingProperties) noexcept = 0;
    virtual int32_t WINRT_CALL ProcessFrame(void* context) noexcept = 0;
    virtual int32_t WINRT_CALL Close(Windows::Media::Effects::MediaEffectClosedReason reason) noexcept = 0;
    virtual int32_t WINRT_CALL DiscardQueuedFrames() noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IBasicVideoEffect>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedMemoryTypes(Windows::Media::Effects::MediaMemoryTypes* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeIndependent(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedEncodingProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetEncodingProperties(void* encodingProperties, void* device) noexcept = 0;
    virtual int32_t WINRT_CALL ProcessFrame(void* context) noexcept = 0;
    virtual int32_t WINRT_CALL Close(Windows::Media::Effects::MediaEffectClosedReason reason) noexcept = 0;
    virtual int32_t WINRT_CALL DiscardQueuedFrames() noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::ICompositeVideoFrameContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SurfacesToOverlay(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundFrame(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutputFrame(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetOverlayForSurface(void* surfaceToOverlay, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IProcessAudioFrameContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InputFrame(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutputFrame(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IProcessVideoFrameContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InputFrame(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutputFrame(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoCompositor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TimeIndependent(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetEncodingProperties(void* backgroundProperties, void* device) noexcept = 0;
    virtual int32_t WINRT_CALL CompositeFrame(void* context) noexcept = 0;
    virtual int32_t WINRT_CALL Close(Windows::Media::Effects::MediaEffectClosedReason reason) noexcept = 0;
    virtual int32_t WINRT_CALL DiscardQueuedFrames() noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoCompositorDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivatableClassId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoCompositorDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* activatableClassId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivatableClassId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoEffectDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* activatableClassId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoTransformEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PaddingColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PaddingColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutputSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OutputSize(Windows::Foundation::Size value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CropRectangle(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CropRectangle(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rotation(Windows::Media::MediaProperties::MediaRotation* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Rotation(Windows::Media::MediaProperties::MediaRotation value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mirror(Windows::Media::MediaProperties::MediaMirroringOptions* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mirror(Windows::Media::MediaProperties::MediaMirroringOptions value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoTransformEffectDefinition2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SphericalProjection(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Effects::IVideoTransformSphericalProjection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HorizontalFieldOfViewInDegrees(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HorizontalFieldOfViewInDegrees(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ViewOrientation(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ViewOrientation(Windows::Foundation::Numerics::quaternion value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Effects_IAudioCaptureEffectsManager
{
    winrt::event_token AudioCaptureEffectsChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioCaptureEffectsManager, Windows::Foundation::IInspectable> const& handler) const;
    using AudioCaptureEffectsChanged_revoker = impl::event_revoker<Windows::Media::Effects::IAudioCaptureEffectsManager, &impl::abi_t<Windows::Media::Effects::IAudioCaptureEffectsManager>::remove_AudioCaptureEffectsChanged>;
    AudioCaptureEffectsChanged_revoker AudioCaptureEffectsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioCaptureEffectsManager, Windows::Foundation::IInspectable> const& handler) const;
    void AudioCaptureEffectsChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect> GetAudioCaptureEffects() const;
};
template <> struct consume<Windows::Media::Effects::IAudioCaptureEffectsManager> { template <typename D> using type = consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IAudioEffect
{
    Windows::Media::Effects::AudioEffectType AudioEffectType() const;
};
template <> struct consume<Windows::Media::Effects::IAudioEffect> { template <typename D> using type = consume_Windows_Media_Effects_IAudioEffect<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IAudioEffectDefinition
{
    hstring ActivatableClassId() const;
    Windows::Foundation::Collections::IPropertySet Properties() const;
};
template <> struct consume<Windows::Media::Effects::IAudioEffectDefinition> { template <typename D> using type = consume_Windows_Media_Effects_IAudioEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IAudioEffectDefinitionFactory
{
    Windows::Media::Effects::AudioEffectDefinition Create(param::hstring const& activatableClassId) const;
    Windows::Media::Effects::AudioEffectDefinition CreateWithProperties(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) const;
};
template <> struct consume<Windows::Media::Effects::IAudioEffectDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Effects_IAudioEffectDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IAudioEffectsManagerStatics
{
    Windows::Media::Effects::AudioRenderEffectsManager CreateAudioRenderEffectsManager(param::hstring const& deviceId, Windows::Media::Render::AudioRenderCategory const& category) const;
    Windows::Media::Effects::AudioRenderEffectsManager CreateAudioRenderEffectsManager(param::hstring const& deviceId, Windows::Media::Render::AudioRenderCategory const& category, Windows::Media::AudioProcessing const& mode) const;
    Windows::Media::Effects::AudioCaptureEffectsManager CreateAudioCaptureEffectsManager(param::hstring const& deviceId, Windows::Media::Capture::MediaCategory const& category) const;
    Windows::Media::Effects::AudioCaptureEffectsManager CreateAudioCaptureEffectsManager(param::hstring const& deviceId, Windows::Media::Capture::MediaCategory const& category, Windows::Media::AudioProcessing const& mode) const;
};
template <> struct consume<Windows::Media::Effects::IAudioEffectsManagerStatics> { template <typename D> using type = consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IAudioRenderEffectsManager
{
    winrt::event_token AudioRenderEffectsChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioRenderEffectsManager, Windows::Foundation::IInspectable> const& handler) const;
    using AudioRenderEffectsChanged_revoker = impl::event_revoker<Windows::Media::Effects::IAudioRenderEffectsManager, &impl::abi_t<Windows::Media::Effects::IAudioRenderEffectsManager>::remove_AudioRenderEffectsChanged>;
    AudioRenderEffectsChanged_revoker AudioRenderEffectsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Effects::AudioRenderEffectsManager, Windows::Foundation::IInspectable> const& handler) const;
    void AudioRenderEffectsChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Effects::AudioEffect> GetAudioRenderEffects() const;
};
template <> struct consume<Windows::Media::Effects::IAudioRenderEffectsManager> { template <typename D> using type = consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IAudioRenderEffectsManager2
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType EffectsProviderThumbnail() const;
    hstring EffectsProviderSettingsLabel() const;
    void ShowSettingsUI() const;
};
template <> struct consume<Windows::Media::Effects::IAudioRenderEffectsManager2> { template <typename D> using type = consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IBasicAudioEffect
{
    bool UseInputFrameForOutput() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::AudioEncodingProperties> SupportedEncodingProperties() const;
    void SetEncodingProperties(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const;
    void ProcessFrame(Windows::Media::Effects::ProcessAudioFrameContext const& context) const;
    void Close(Windows::Media::Effects::MediaEffectClosedReason const& reason) const;
    void DiscardQueuedFrames() const;
};
template <> struct consume<Windows::Media::Effects::IBasicAudioEffect> { template <typename D> using type = consume_Windows_Media_Effects_IBasicAudioEffect<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IBasicVideoEffect
{
    bool IsReadOnly() const;
    Windows::Media::Effects::MediaMemoryTypes SupportedMemoryTypes() const;
    bool TimeIndependent() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaProperties::VideoEncodingProperties> SupportedEncodingProperties() const;
    void SetEncodingProperties(Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const;
    void ProcessFrame(Windows::Media::Effects::ProcessVideoFrameContext const& context) const;
    void Close(Windows::Media::Effects::MediaEffectClosedReason const& reason) const;
    void DiscardQueuedFrames() const;
};
template <> struct consume<Windows::Media::Effects::IBasicVideoEffect> { template <typename D> using type = consume_Windows_Media_Effects_IBasicVideoEffect<D>; };

template <typename D>
struct consume_Windows_Media_Effects_ICompositeVideoFrameContext
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface> SurfacesToOverlay() const;
    Windows::Media::VideoFrame BackgroundFrame() const;
    Windows::Media::VideoFrame OutputFrame() const;
    Windows::Media::Editing::MediaOverlay GetOverlayForSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surfaceToOverlay) const;
};
template <> struct consume<Windows::Media::Effects::ICompositeVideoFrameContext> { template <typename D> using type = consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IProcessAudioFrameContext
{
    Windows::Media::AudioFrame InputFrame() const;
    Windows::Media::AudioFrame OutputFrame() const;
};
template <> struct consume<Windows::Media::Effects::IProcessAudioFrameContext> { template <typename D> using type = consume_Windows_Media_Effects_IProcessAudioFrameContext<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IProcessVideoFrameContext
{
    Windows::Media::VideoFrame InputFrame() const;
    Windows::Media::VideoFrame OutputFrame() const;
};
template <> struct consume<Windows::Media::Effects::IProcessVideoFrameContext> { template <typename D> using type = consume_Windows_Media_Effects_IProcessVideoFrameContext<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoCompositor
{
    bool TimeIndependent() const;
    void SetEncodingProperties(Windows::Media::MediaProperties::VideoEncodingProperties const& backgroundProperties, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const;
    void CompositeFrame(Windows::Media::Effects::CompositeVideoFrameContext const& context) const;
    void Close(Windows::Media::Effects::MediaEffectClosedReason const& reason) const;
    void DiscardQueuedFrames() const;
};
template <> struct consume<Windows::Media::Effects::IVideoCompositor> { template <typename D> using type = consume_Windows_Media_Effects_IVideoCompositor<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoCompositorDefinition
{
    hstring ActivatableClassId() const;
    Windows::Foundation::Collections::IPropertySet Properties() const;
};
template <> struct consume<Windows::Media::Effects::IVideoCompositorDefinition> { template <typename D> using type = consume_Windows_Media_Effects_IVideoCompositorDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoCompositorDefinitionFactory
{
    Windows::Media::Effects::VideoCompositorDefinition Create(param::hstring const& activatableClassId) const;
    Windows::Media::Effects::VideoCompositorDefinition CreateWithProperties(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) const;
};
template <> struct consume<Windows::Media::Effects::IVideoCompositorDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Effects_IVideoCompositorDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoEffectDefinition
{
    hstring ActivatableClassId() const;
    Windows::Foundation::Collections::IPropertySet Properties() const;
};
template <> struct consume<Windows::Media::Effects::IVideoEffectDefinition> { template <typename D> using type = consume_Windows_Media_Effects_IVideoEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoEffectDefinitionFactory
{
    Windows::Media::Effects::VideoEffectDefinition Create(param::hstring const& activatableClassId) const;
    Windows::Media::Effects::VideoEffectDefinition CreateWithProperties(param::hstring const& activatableClassId, Windows::Foundation::Collections::IPropertySet const& props) const;
};
template <> struct consume<Windows::Media::Effects::IVideoEffectDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Effects_IVideoEffectDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoTransformEffectDefinition
{
    Windows::UI::Color PaddingColor() const;
    void PaddingColor(Windows::UI::Color const& value) const;
    Windows::Foundation::Size OutputSize() const;
    void OutputSize(Windows::Foundation::Size const& value) const;
    Windows::Foundation::Rect CropRectangle() const;
    void CropRectangle(Windows::Foundation::Rect const& value) const;
    Windows::Media::MediaProperties::MediaRotation Rotation() const;
    void Rotation(Windows::Media::MediaProperties::MediaRotation const& value) const;
    Windows::Media::MediaProperties::MediaMirroringOptions Mirror() const;
    void Mirror(Windows::Media::MediaProperties::MediaMirroringOptions const& value) const;
    void ProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const& value) const;
    Windows::Media::Transcoding::MediaVideoProcessingAlgorithm ProcessingAlgorithm() const;
};
template <> struct consume<Windows::Media::Effects::IVideoTransformEffectDefinition> { template <typename D> using type = consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoTransformEffectDefinition2
{
    Windows::Media::Effects::VideoTransformSphericalProjection SphericalProjection() const;
};
template <> struct consume<Windows::Media::Effects::IVideoTransformEffectDefinition2> { template <typename D> using type = consume_Windows_Media_Effects_IVideoTransformEffectDefinition2<D>; };

template <typename D>
struct consume_Windows_Media_Effects_IVideoTransformSphericalProjection
{
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    Windows::Media::MediaProperties::SphericalVideoFrameFormat FrameFormat() const;
    void FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat const& value) const;
    Windows::Media::Playback::SphericalVideoProjectionMode ProjectionMode() const;
    void ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode const& value) const;
    double HorizontalFieldOfViewInDegrees() const;
    void HorizontalFieldOfViewInDegrees(double value) const;
    Windows::Foundation::Numerics::quaternion ViewOrientation() const;
    void ViewOrientation(Windows::Foundation::Numerics::quaternion const& value) const;
};
template <> struct consume<Windows::Media::Effects::IVideoTransformSphericalProjection> { template <typename D> using type = consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>; };

}
