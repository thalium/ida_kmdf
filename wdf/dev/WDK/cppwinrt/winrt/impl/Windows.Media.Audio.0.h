// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

struct DeviceInformation;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Media {

enum class AudioProcessing;
enum class SoundLevel;
struct AudioFrame;

}

WINRT_EXPORT namespace winrt::Windows::Media::Capture {

enum class MediaCategory;

}

WINRT_EXPORT namespace winrt::Windows::Media::Core {

struct MediaSource;

}

WINRT_EXPORT namespace winrt::Windows::Media::Devices {

enum class AudioDeviceRole;

}

WINRT_EXPORT namespace winrt::Windows::Media::Effects {

struct IAudioEffectDefinition;

}

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

struct AudioEncodingProperties;
struct MediaEncodingProfile;

}

WINRT_EXPORT namespace winrt::Windows::Media::Render {

enum class AudioRenderCategory;

}

WINRT_EXPORT namespace winrt::Windows::Media::Transcoding {

enum class TranscodeFailureReason;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;
struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct IClosable;

}

WINRT_EXPORT namespace winrt::Windows::Media::Audio {

enum class AudioDeviceNodeCreationStatus : int32_t
{
    Success = 0,
    DeviceNotAvailable = 1,
    FormatNotSupported = 2,
    UnknownFailure = 3,
    AccessDenied = 4,
};

enum class AudioFileNodeCreationStatus : int32_t
{
    Success = 0,
    FileNotFound = 1,
    InvalidFileType = 2,
    FormatNotSupported = 3,
    UnknownFailure = 4,
};

enum class AudioGraphCreationStatus : int32_t
{
    Success = 0,
    DeviceNotAvailable = 1,
    FormatNotSupported = 2,
    UnknownFailure = 3,
};

enum class AudioGraphUnrecoverableError : int32_t
{
    None = 0,
    AudioDeviceLost = 1,
    AudioSessionDisconnected = 2,
    UnknownFailure = 3,
};

enum class AudioNodeEmitterDecayKind : int32_t
{
    Natural = 0,
    Custom = 1,
};

enum class AudioNodeEmitterSettings : uint32_t
{
    None = 0x0,
    DisableDoppler = 0x1,
};

enum class AudioNodeEmitterShapeKind : int32_t
{
    Omnidirectional = 0,
    Cone = 1,
};

enum class MediaSourceAudioInputNodeCreationStatus : int32_t
{
    Success = 0,
    FormatNotSupported = 1,
    NetworkError = 2,
    UnknownFailure = 3,
};

enum class MixedRealitySpatialAudioFormatPolicy : int32_t
{
    UseMixedRealityDefaultSpatialAudioFormat = 0,
    UseDeviceConfigurationDefaultSpatialAudioFormat = 1,
};

enum class QuantumSizeSelectionMode : int32_t
{
    SystemDefault = 0,
    LowestLatency = 1,
    ClosestToDesired = 2,
};

enum class SetDefaultSpatialAudioFormatStatus : int32_t
{
    Succeeded = 0,
    AccessDenied = 1,
    LicenseExpired = 2,
    LicenseNotValidForAudioEndpoint = 3,
    NotSupportedOnAudioEndpoint = 4,
    UnknownError = 5,
};

enum class SpatialAudioModel : int32_t
{
    ObjectBased = 0,
    FoldDown = 1,
};

struct IAudioDeviceInputNode;
struct IAudioDeviceOutputNode;
struct IAudioFileInputNode;
struct IAudioFileOutputNode;
struct IAudioFrameCompletedEventArgs;
struct IAudioFrameInputNode;
struct IAudioFrameOutputNode;
struct IAudioGraph;
struct IAudioGraph2;
struct IAudioGraph3;
struct IAudioGraphConnection;
struct IAudioGraphSettings;
struct IAudioGraphSettings2;
struct IAudioGraphSettingsFactory;
struct IAudioGraphStatics;
struct IAudioGraphUnrecoverableErrorOccurredEventArgs;
struct IAudioInputNode;
struct IAudioInputNode2;
struct IAudioNode;
struct IAudioNodeEmitter;
struct IAudioNodeEmitter2;
struct IAudioNodeEmitterConeProperties;
struct IAudioNodeEmitterDecayModel;
struct IAudioNodeEmitterDecayModelStatics;
struct IAudioNodeEmitterFactory;
struct IAudioNodeEmitterNaturalDecayModelProperties;
struct IAudioNodeEmitterShape;
struct IAudioNodeEmitterShapeStatics;
struct IAudioNodeListener;
struct IAudioNodeWithListener;
struct IAudioStateMonitor;
struct IAudioStateMonitorStatics;
struct ICreateAudioDeviceInputNodeResult;
struct ICreateAudioDeviceInputNodeResult2;
struct ICreateAudioDeviceOutputNodeResult;
struct ICreateAudioDeviceOutputNodeResult2;
struct ICreateAudioFileInputNodeResult;
struct ICreateAudioFileInputNodeResult2;
struct ICreateAudioFileOutputNodeResult;
struct ICreateAudioFileOutputNodeResult2;
struct ICreateAudioGraphResult;
struct ICreateAudioGraphResult2;
struct ICreateMediaSourceAudioInputNodeResult;
struct ICreateMediaSourceAudioInputNodeResult2;
struct IEchoEffectDefinition;
struct IEchoEffectDefinitionFactory;
struct IEqualizerBand;
struct IEqualizerEffectDefinition;
struct IEqualizerEffectDefinitionFactory;
struct IFrameInputNodeQuantumStartedEventArgs;
struct ILimiterEffectDefinition;
struct ILimiterEffectDefinitionFactory;
struct IMediaSourceAudioInputNode;
struct IReverbEffectDefinition;
struct IReverbEffectDefinitionFactory;
struct ISetDefaultSpatialAudioFormatResult;
struct ISpatialAudioDeviceConfiguration;
struct ISpatialAudioDeviceConfigurationStatics;
struct ISpatialAudioFormatConfiguration;
struct ISpatialAudioFormatConfigurationStatics;
struct ISpatialAudioFormatSubtypeStatics;
struct AudioDeviceInputNode;
struct AudioDeviceOutputNode;
struct AudioFileInputNode;
struct AudioFileOutputNode;
struct AudioFrameCompletedEventArgs;
struct AudioFrameInputNode;
struct AudioFrameOutputNode;
struct AudioGraph;
struct AudioGraphBatchUpdater;
struct AudioGraphConnection;
struct AudioGraphSettings;
struct AudioGraphUnrecoverableErrorOccurredEventArgs;
struct AudioNodeEmitter;
struct AudioNodeEmitterConeProperties;
struct AudioNodeEmitterDecayModel;
struct AudioNodeEmitterNaturalDecayModelProperties;
struct AudioNodeEmitterShape;
struct AudioNodeListener;
struct AudioStateMonitor;
struct AudioSubmixNode;
struct CreateAudioDeviceInputNodeResult;
struct CreateAudioDeviceOutputNodeResult;
struct CreateAudioFileInputNodeResult;
struct CreateAudioFileOutputNodeResult;
struct CreateAudioGraphResult;
struct CreateMediaSourceAudioInputNodeResult;
struct EchoEffectDefinition;
struct EqualizerBand;
struct EqualizerEffectDefinition;
struct FrameInputNodeQuantumStartedEventArgs;
struct LimiterEffectDefinition;
struct MediaSourceAudioInputNode;
struct ReverbEffectDefinition;
struct SetDefaultSpatialAudioFormatResult;
struct SpatialAudioDeviceConfiguration;
struct SpatialAudioFormatConfiguration;
struct SpatialAudioFormatSubtype;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Media::Audio::AudioNodeEmitterSettings> : std::true_type {};
template <> struct category<Windows::Media::Audio::IAudioDeviceInputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioDeviceOutputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioFileInputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioFileOutputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioFrameCompletedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioFrameInputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioFrameOutputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraph>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraph2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraph3>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraphConnection>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraphSettings>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraphSettings2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraphSettingsFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraphStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioInputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioInputNode2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitter>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitter2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterConeProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterDecayModel>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterShape>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeEmitterShapeStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeListener>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioNodeWithListener>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioStateMonitor>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IAudioStateMonitorStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioFileInputNodeResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioFileInputNodeResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioFileOutputNodeResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioFileOutputNodeResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioGraphResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateAudioGraphResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IEchoEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IEchoEffectDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IEqualizerBand>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IEqualizerEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IEqualizerEffectDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ILimiterEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ILimiterEffectDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IMediaSourceAudioInputNode>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IReverbEffectDefinition>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::IReverbEffectDefinitionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ISpatialAudioDeviceConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ISpatialAudioFormatConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Audio::AudioDeviceInputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioDeviceOutputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioFileInputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioFileOutputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioFrameCompletedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioFrameInputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioFrameOutputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioGraph>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioGraphBatchUpdater>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioGraphConnection>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioGraphSettings>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitter>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterConeProperties>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterDecayModel>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterShape>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioNodeListener>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioStateMonitor>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioSubmixNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::CreateAudioDeviceOutputNodeResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::CreateAudioFileInputNodeResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::CreateAudioFileOutputNodeResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::CreateAudioGraphResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::EchoEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::EqualizerBand>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::EqualizerEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::LimiterEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::MediaSourceAudioInputNode>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::ReverbEffectDefinition>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::SetDefaultSpatialAudioFormatResult>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::SpatialAudioDeviceConfiguration>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::SpatialAudioFormatConfiguration>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::SpatialAudioFormatSubtype>{ using type = class_category; };
template <> struct category<Windows::Media::Audio::AudioDeviceNodeCreationStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::AudioFileNodeCreationStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::AudioGraphCreationStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::AudioGraphUnrecoverableError>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterDecayKind>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterSettings>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::AudioNodeEmitterShapeKind>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::QuantumSizeSelectionMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Audio::SpatialAudioModel>{ using type = enum_category; };
template <> struct name<Windows::Media::Audio::IAudioDeviceInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioDeviceInputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioDeviceOutputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioDeviceOutputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioFileInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioFileInputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioFileOutputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioFileOutputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioFrameCompletedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioFrameCompletedEventArgs" }; };
template <> struct name<Windows::Media::Audio::IAudioFrameInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioFrameInputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioFrameOutputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioFrameOutputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioGraph>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraph" }; };
template <> struct name<Windows::Media::Audio::IAudioGraph2>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraph2" }; };
template <> struct name<Windows::Media::Audio::IAudioGraph3>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraph3" }; };
template <> struct name<Windows::Media::Audio::IAudioGraphConnection>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraphConnection" }; };
template <> struct name<Windows::Media::Audio::IAudioGraphSettings>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraphSettings" }; };
template <> struct name<Windows::Media::Audio::IAudioGraphSettings2>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraphSettings2" }; };
template <> struct name<Windows::Media::Audio::IAudioGraphSettingsFactory>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraphSettingsFactory" }; };
template <> struct name<Windows::Media::Audio::IAudioGraphStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraphStatics" }; };
template <> struct name<Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioGraphUnrecoverableErrorOccurredEventArgs" }; };
template <> struct name<Windows::Media::Audio::IAudioInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioInputNode" }; };
template <> struct name<Windows::Media::Audio::IAudioInputNode2>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioInputNode2" }; };
template <> struct name<Windows::Media::Audio::IAudioNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNode" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitter>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitter" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitter2>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitter2" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterConeProperties>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterConeProperties" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterDecayModel>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterDecayModel" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterDecayModelStatics" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterFactory>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterFactory" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterNaturalDecayModelProperties" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterShape>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterShape" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeEmitterShapeStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeEmitterShapeStatics" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeListener>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeListener" }; };
template <> struct name<Windows::Media::Audio::IAudioNodeWithListener>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioNodeWithListener" }; };
template <> struct name<Windows::Media::Audio::IAudioStateMonitor>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioStateMonitor" }; };
template <> struct name<Windows::Media::Audio::IAudioStateMonitorStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.IAudioStateMonitorStatics" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioDeviceInputNodeResult" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioDeviceInputNodeResult2" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioDeviceOutputNodeResult" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioDeviceOutputNodeResult2" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioFileInputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioFileInputNodeResult" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioFileInputNodeResult2>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioFileInputNodeResult2" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioFileOutputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioFileOutputNodeResult" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioFileOutputNodeResult2>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioFileOutputNodeResult2" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioGraphResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioGraphResult" }; };
template <> struct name<Windows::Media::Audio::ICreateAudioGraphResult2>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateAudioGraphResult2" }; };
template <> struct name<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateMediaSourceAudioInputNodeResult" }; };
template <> struct name<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2>{ static constexpr auto & value{ L"Windows.Media.Audio.ICreateMediaSourceAudioInputNodeResult2" }; };
template <> struct name<Windows::Media::Audio::IEchoEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.IEchoEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::IEchoEffectDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Audio.IEchoEffectDefinitionFactory" }; };
template <> struct name<Windows::Media::Audio::IEqualizerBand>{ static constexpr auto & value{ L"Windows.Media.Audio.IEqualizerBand" }; };
template <> struct name<Windows::Media::Audio::IEqualizerEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.IEqualizerEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::IEqualizerEffectDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Audio.IEqualizerEffectDefinitionFactory" }; };
template <> struct name<Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Audio.IFrameInputNodeQuantumStartedEventArgs" }; };
template <> struct name<Windows::Media::Audio::ILimiterEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.ILimiterEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::ILimiterEffectDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Audio.ILimiterEffectDefinitionFactory" }; };
template <> struct name<Windows::Media::Audio::IMediaSourceAudioInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.IMediaSourceAudioInputNode" }; };
template <> struct name<Windows::Media::Audio::IReverbEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.IReverbEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::IReverbEffectDefinitionFactory>{ static constexpr auto & value{ L"Windows.Media.Audio.IReverbEffectDefinitionFactory" }; };
template <> struct name<Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult>{ static constexpr auto & value{ L"Windows.Media.Audio.ISetDefaultSpatialAudioFormatResult" }; };
template <> struct name<Windows::Media::Audio::ISpatialAudioDeviceConfiguration>{ static constexpr auto & value{ L"Windows.Media.Audio.ISpatialAudioDeviceConfiguration" }; };
template <> struct name<Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.ISpatialAudioDeviceConfigurationStatics" }; };
template <> struct name<Windows::Media::Audio::ISpatialAudioFormatConfiguration>{ static constexpr auto & value{ L"Windows.Media.Audio.ISpatialAudioFormatConfiguration" }; };
template <> struct name<Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.ISpatialAudioFormatConfigurationStatics" }; };
template <> struct name<Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics>{ static constexpr auto & value{ L"Windows.Media.Audio.ISpatialAudioFormatSubtypeStatics" }; };
template <> struct name<Windows::Media::Audio::AudioDeviceInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioDeviceInputNode" }; };
template <> struct name<Windows::Media::Audio::AudioDeviceOutputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioDeviceOutputNode" }; };
template <> struct name<Windows::Media::Audio::AudioFileInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioFileInputNode" }; };
template <> struct name<Windows::Media::Audio::AudioFileOutputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioFileOutputNode" }; };
template <> struct name<Windows::Media::Audio::AudioFrameCompletedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioFrameCompletedEventArgs" }; };
template <> struct name<Windows::Media::Audio::AudioFrameInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioFrameInputNode" }; };
template <> struct name<Windows::Media::Audio::AudioFrameOutputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioFrameOutputNode" }; };
template <> struct name<Windows::Media::Audio::AudioGraph>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraph" }; };
template <> struct name<Windows::Media::Audio::AudioGraphBatchUpdater>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraphBatchUpdater" }; };
template <> struct name<Windows::Media::Audio::AudioGraphConnection>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraphConnection" }; };
template <> struct name<Windows::Media::Audio::AudioGraphSettings>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraphSettings" }; };
template <> struct name<Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraphUnrecoverableErrorOccurredEventArgs" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitter>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitter" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterConeProperties>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterConeProperties" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterDecayModel>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterDecayModel" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterNaturalDecayModelProperties" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterShape>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterShape" }; };
template <> struct name<Windows::Media::Audio::AudioNodeListener>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeListener" }; };
template <> struct name<Windows::Media::Audio::AudioStateMonitor>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioStateMonitor" }; };
template <> struct name<Windows::Media::Audio::AudioSubmixNode>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioSubmixNode" }; };
template <> struct name<Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.CreateAudioDeviceInputNodeResult" }; };
template <> struct name<Windows::Media::Audio::CreateAudioDeviceOutputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.CreateAudioDeviceOutputNodeResult" }; };
template <> struct name<Windows::Media::Audio::CreateAudioFileInputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.CreateAudioFileInputNodeResult" }; };
template <> struct name<Windows::Media::Audio::CreateAudioFileOutputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.CreateAudioFileOutputNodeResult" }; };
template <> struct name<Windows::Media::Audio::CreateAudioGraphResult>{ static constexpr auto & value{ L"Windows.Media.Audio.CreateAudioGraphResult" }; };
template <> struct name<Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>{ static constexpr auto & value{ L"Windows.Media.Audio.CreateMediaSourceAudioInputNodeResult" }; };
template <> struct name<Windows::Media::Audio::EchoEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.EchoEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::EqualizerBand>{ static constexpr auto & value{ L"Windows.Media.Audio.EqualizerBand" }; };
template <> struct name<Windows::Media::Audio::EqualizerEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.EqualizerEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Audio.FrameInputNodeQuantumStartedEventArgs" }; };
template <> struct name<Windows::Media::Audio::LimiterEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.LimiterEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::MediaSourceAudioInputNode>{ static constexpr auto & value{ L"Windows.Media.Audio.MediaSourceAudioInputNode" }; };
template <> struct name<Windows::Media::Audio::ReverbEffectDefinition>{ static constexpr auto & value{ L"Windows.Media.Audio.ReverbEffectDefinition" }; };
template <> struct name<Windows::Media::Audio::SetDefaultSpatialAudioFormatResult>{ static constexpr auto & value{ L"Windows.Media.Audio.SetDefaultSpatialAudioFormatResult" }; };
template <> struct name<Windows::Media::Audio::SpatialAudioDeviceConfiguration>{ static constexpr auto & value{ L"Windows.Media.Audio.SpatialAudioDeviceConfiguration" }; };
template <> struct name<Windows::Media::Audio::SpatialAudioFormatConfiguration>{ static constexpr auto & value{ L"Windows.Media.Audio.SpatialAudioFormatConfiguration" }; };
template <> struct name<Windows::Media::Audio::SpatialAudioFormatSubtype>{ static constexpr auto & value{ L"Windows.Media.Audio.SpatialAudioFormatSubtype" }; };
template <> struct name<Windows::Media::Audio::AudioDeviceNodeCreationStatus>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioDeviceNodeCreationStatus" }; };
template <> struct name<Windows::Media::Audio::AudioFileNodeCreationStatus>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioFileNodeCreationStatus" }; };
template <> struct name<Windows::Media::Audio::AudioGraphCreationStatus>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraphCreationStatus" }; };
template <> struct name<Windows::Media::Audio::AudioGraphUnrecoverableError>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioGraphUnrecoverableError" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterDecayKind>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterDecayKind" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterSettings>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterSettings" }; };
template <> struct name<Windows::Media::Audio::AudioNodeEmitterShapeKind>{ static constexpr auto & value{ L"Windows.Media.Audio.AudioNodeEmitterShapeKind" }; };
template <> struct name<Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus>{ static constexpr auto & value{ L"Windows.Media.Audio.MediaSourceAudioInputNodeCreationStatus" }; };
template <> struct name<Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy>{ static constexpr auto & value{ L"Windows.Media.Audio.MixedRealitySpatialAudioFormatPolicy" }; };
template <> struct name<Windows::Media::Audio::QuantumSizeSelectionMode>{ static constexpr auto & value{ L"Windows.Media.Audio.QuantumSizeSelectionMode" }; };
template <> struct name<Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus>{ static constexpr auto & value{ L"Windows.Media.Audio.SetDefaultSpatialAudioFormatStatus" }; };
template <> struct name<Windows::Media::Audio::SpatialAudioModel>{ static constexpr auto & value{ L"Windows.Media.Audio.SpatialAudioModel" }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioDeviceInputNode>{ static constexpr guid value{ 0xB01B6BE1,0x6F4E,0x49E2,{ 0xAC,0x01,0x55,0x9D,0x62,0xBE,0xB3,0xA9 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioDeviceOutputNode>{ static constexpr guid value{ 0x362EDBFF,0xFF1C,0x4434,{ 0x9E,0x0F,0xBD,0x2E,0xF5,0x22,0xAC,0x82 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioFileInputNode>{ static constexpr guid value{ 0x905B67C8,0x6F65,0x4CD4,{ 0x88,0x90,0x46,0x94,0x84,0x3C,0x27,0x6D } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioFileOutputNode>{ static constexpr guid value{ 0x50E01980,0x5166,0x4093,{ 0x80,0xF8,0xAD,0xA0,0x00,0x89,0xE9,0xCF } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioFrameCompletedEventArgs>{ static constexpr guid value{ 0xDC7C829E,0x0208,0x4504,{ 0xA5,0xA8,0xF0,0xF2,0x68,0x92,0x0A,0x65 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioFrameInputNode>{ static constexpr guid value{ 0x01B266C7,0xFD96,0x4FF5,{ 0xA3,0xC5,0xD2,0x7A,0x9B,0xF4,0x42,0x37 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioFrameOutputNode>{ static constexpr guid value{ 0xB847371B,0x3299,0x45F5,{ 0x88,0xB3,0xC9,0xD1,0x2A,0x3F,0x1C,0xC8 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraph>{ static constexpr guid value{ 0x1AD46EED,0xE48C,0x4E14,{ 0x96,0x60,0x2C,0x4F,0x83,0xE9,0xCD,0xD8 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraph2>{ static constexpr guid value{ 0x4E4C3BD5,0x4FC1,0x45F6,{ 0xA9,0x47,0x3C,0xD3,0x8F,0x4F,0xD8,0x39 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraph3>{ static constexpr guid value{ 0xDDCD25AE,0x1185,0x42A7,{ 0x83,0x1D,0x6A,0x9B,0x0F,0xC8,0x68,0x20 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraphConnection>{ static constexpr guid value{ 0x763070ED,0xD04E,0x4FAC,{ 0xB2,0x33,0x60,0x0B,0x42,0xED,0xD4,0x69 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraphSettings>{ static constexpr guid value{ 0x1D59647F,0xE6FE,0x4628,{ 0x84,0xF8,0x9D,0x8B,0xDB,0xA2,0x57,0x85 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraphSettings2>{ static constexpr guid value{ 0x72919787,0x4DAB,0x46E3,{ 0xB4,0xC9,0xD8,0xE1,0xA2,0x63,0x60,0x62 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraphSettingsFactory>{ static constexpr guid value{ 0xA5D91CC6,0xC2EB,0x4A61,{ 0xA2,0x14,0x1D,0x66,0xD7,0x5F,0x83,0xDA } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraphStatics>{ static constexpr guid value{ 0x76EC3132,0xE159,0x4AB7,{ 0xA8,0x2A,0x17,0xBE,0xB4,0xB3,0x1E,0x94 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs>{ static constexpr guid value{ 0xC3D9CBE0,0x3FF6,0x4FB3,{ 0xB2,0x62,0x50,0xD4,0x35,0xC5,0x54,0x23 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioInputNode>{ static constexpr guid value{ 0xD148005C,0x8428,0x4784,{ 0xB7,0xFD,0xA9,0x9D,0x46,0x8C,0x5D,0x20 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioInputNode2>{ static constexpr guid value{ 0x905156B7,0xCA68,0x4C6D,{ 0xA8,0xBC,0xE3,0xEE,0x17,0xFE,0x3F,0xD2 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNode>{ static constexpr guid value{ 0x15389D7F,0xDBD8,0x4819,{ 0xBF,0x03,0x66,0x8E,0x93,0x57,0xCD,0x6D } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitter>{ static constexpr guid value{ 0x3676971D,0x880A,0x47B8,{ 0xAD,0xF7,0x13,0x23,0xA9,0xD9,0x65,0xBE } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitter2>{ static constexpr guid value{ 0x4AB6EECB,0xEC29,0x47F8,{ 0x81,0x8C,0xB6,0xB6,0x60,0xA5,0xAE,0xB1 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterConeProperties>{ static constexpr guid value{ 0xE99B2CEE,0x02CA,0x4375,{ 0x93,0x26,0x0C,0x6A,0xE4,0xBC,0xDF,0xB5 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterDecayModel>{ static constexpr guid value{ 0x1D1D5AF7,0x0D53,0x4FA9,{ 0xBD,0x84,0xD5,0x81,0x6A,0x86,0xF3,0xFF } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics>{ static constexpr guid value{ 0xC7787CA8,0xF178,0x462F,{ 0xBC,0x81,0x8D,0xD5,0xCB,0xE5,0xDA,0xE8 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterFactory>{ static constexpr guid value{ 0xFDC8489A,0x6AD6,0x4CE4,{ 0xB7,0xF7,0xA9,0x93,0x70,0xDF,0x7E,0xE9 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties>{ static constexpr guid value{ 0x48934BCF,0xCF2C,0x4EFC,{ 0x93,0x31,0x75,0xBD,0x22,0xDF,0x1F,0x0C } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterShape>{ static constexpr guid value{ 0xEA0311C5,0xE73D,0x44BC,{ 0x85,0x9C,0x45,0x55,0x3B,0xBC,0x48,0x28 } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeEmitterShapeStatics>{ static constexpr guid value{ 0x57BB2771,0xFFA5,0x4B86,{ 0xA7,0x79,0xE2,0x64,0xAE,0xB9,0x14,0x5F } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeListener>{ static constexpr guid value{ 0xD9722E16,0x0C0A,0x41DA,{ 0xB7,0x55,0x6C,0x77,0x83,0x5F,0xB1,0xEB } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioNodeWithListener>{ static constexpr guid value{ 0x0E0F907C,0x79FF,0x4544,{ 0x9E,0xEB,0x01,0x25,0x7B,0x15,0x10,0x5A } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioStateMonitor>{ static constexpr guid value{ 0x1D13D136,0x0199,0x4CDC,{ 0xB8,0x4E,0xE7,0x2C,0x2B,0x58,0x1E,0xCE } }; };
template <> struct guid_storage<Windows::Media::Audio::IAudioStateMonitorStatics>{ static constexpr guid value{ 0x6374EA4C,0x1B3B,0x4001,{ 0x94,0xD9,0xDD,0x22,0x53,0x30,0xFA,0x40 } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult>{ static constexpr guid value{ 0x16EEC7A8,0x1CA7,0x40EF,{ 0x91,0xA4,0xD3,0x46,0xE0,0xAA,0x1B,0xBA } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2>{ static constexpr guid value{ 0x921C69CE,0x3F35,0x41C7,{ 0x96,0x22,0x79,0xF6,0x08,0xBA,0xED,0xC2 } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult>{ static constexpr guid value{ 0xF7776D27,0x1D9A,0x47F7,{ 0x9C,0xD4,0x28,0x59,0xCC,0x1B,0x7B,0xFF } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2>{ static constexpr guid value{ 0x4864269F,0xBDCE,0x4AB1,{ 0xBD,0x38,0xFB,0xAE,0x93,0xAE,0xDA,0xCA } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioFileInputNodeResult>{ static constexpr guid value{ 0xCE83D61C,0xE297,0x4C50,{ 0x9C,0xE7,0x1C,0x7A,0x69,0xD6,0xBD,0x09 } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioFileInputNodeResult2>{ static constexpr guid value{ 0xF9082020,0x3D80,0x4FE0,{ 0x81,0xC1,0x76,0x8F,0xEA,0x7C,0xA7,0xE0 } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioFileOutputNodeResult>{ static constexpr guid value{ 0x47D6BA7B,0xE909,0x453F,{ 0x86,0x6E,0x55,0x40,0xCD,0xA7,0x34,0xFF } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioFileOutputNodeResult2>{ static constexpr guid value{ 0x9F01B50D,0x3318,0x47B3,{ 0xA6,0x0A,0x1B,0x49,0x2B,0xE7,0xFC,0x0D } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioGraphResult>{ static constexpr guid value{ 0x5453EF7E,0x7BDE,0x4B76,{ 0xBB,0x5D,0x48,0xF7,0x9C,0xFC,0x8C,0x0B } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateAudioGraphResult2>{ static constexpr guid value{ 0x6D738DFC,0x88C6,0x4FCB,{ 0xA5,0x34,0x85,0xCE,0xDD,0x40,0x50,0xA1 } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult>{ static constexpr guid value{ 0x46A658A3,0x53C0,0x4D59,{ 0x9E,0x51,0xCC,0x1D,0x10,0x44,0xA4,0xC4 } }; };
template <> struct guid_storage<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2>{ static constexpr guid value{ 0x63514CE8,0x6A1A,0x49E3,{ 0x97,0xEC,0x28,0xFD,0x5B,0xE1,0x14,0xE5 } }; };
template <> struct guid_storage<Windows::Media::Audio::IEchoEffectDefinition>{ static constexpr guid value{ 0x0E4D3FAA,0x36B8,0x4C91,{ 0xB9,0xDA,0x11,0xF4,0x4A,0x8A,0x66,0x10 } }; };
template <> struct guid_storage<Windows::Media::Audio::IEchoEffectDefinitionFactory>{ static constexpr guid value{ 0x0D4E2257,0xAAF2,0x4E86,{ 0xA5,0x4C,0xFB,0x79,0xDB,0x8F,0x6C,0x12 } }; };
template <> struct guid_storage<Windows::Media::Audio::IEqualizerBand>{ static constexpr guid value{ 0xC00A5A6A,0x262D,0x4B85,{ 0x9B,0xB7,0x43,0x28,0x0B,0x62,0xED,0x0C } }; };
template <> struct guid_storage<Windows::Media::Audio::IEqualizerEffectDefinition>{ static constexpr guid value{ 0x023F6F1F,0x83FE,0x449A,{ 0xA8,0x22,0xC6,0x96,0x44,0x2D,0x16,0xB0 } }; };
template <> struct guid_storage<Windows::Media::Audio::IEqualizerEffectDefinitionFactory>{ static constexpr guid value{ 0xD2876FC4,0xD410,0x4EB5,{ 0x9E,0x69,0xC9,0xAA,0x12,0x77,0xEA,0xF0 } }; };
template <> struct guid_storage<Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs>{ static constexpr guid value{ 0x3D9BD498,0xA306,0x4F06,{ 0xBD,0x9F,0xE9,0xEF,0xC8,0x22,0x63,0x04 } }; };
template <> struct guid_storage<Windows::Media::Audio::ILimiterEffectDefinition>{ static constexpr guid value{ 0x6B755D19,0x2603,0x47BA,{ 0xBD,0xEB,0x39,0x05,0x5E,0x34,0x86,0xDC } }; };
template <> struct guid_storage<Windows::Media::Audio::ILimiterEffectDefinitionFactory>{ static constexpr guid value{ 0xECBAE6F1,0x61FF,0x45EF,{ 0xB8,0xF5,0x48,0x65,0x9A,0x57,0xC7,0x2D } }; };
template <> struct guid_storage<Windows::Media::Audio::IMediaSourceAudioInputNode>{ static constexpr guid value{ 0x99D8983B,0xA88A,0x4041,{ 0x8E,0x4F,0xDD,0xBA,0xC0,0xC9,0x1F,0xD3 } }; };
template <> struct guid_storage<Windows::Media::Audio::IReverbEffectDefinition>{ static constexpr guid value{ 0x4606AA89,0xF563,0x4D0A,{ 0x8F,0x6E,0xF0,0xCD,0xDF,0xF3,0x5D,0x84 } }; };
template <> struct guid_storage<Windows::Media::Audio::IReverbEffectDefinitionFactory>{ static constexpr guid value{ 0xA7D5CBFE,0x100B,0x4FF0,{ 0x9D,0xA6,0xDC,0x4E,0x05,0xA7,0x59,0xF0 } }; };
template <> struct guid_storage<Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult>{ static constexpr guid value{ 0x1C2AA511,0x1400,0x5E70,{ 0x9E,0xA9,0xAE,0x15,0x12,0x41,0xE8,0xEA } }; };
template <> struct guid_storage<Windows::Media::Audio::ISpatialAudioDeviceConfiguration>{ static constexpr guid value{ 0xEE830034,0x61CF,0x5749,{ 0x9D,0xA4,0x10,0xF0,0xFE,0x02,0x81,0x99 } }; };
template <> struct guid_storage<Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics>{ static constexpr guid value{ 0x3EC37F7B,0x936D,0x4E04,{ 0x97,0x28,0x28,0x27,0xD9,0xF7,0x58,0xC4 } }; };
template <> struct guid_storage<Windows::Media::Audio::ISpatialAudioFormatConfiguration>{ static constexpr guid value{ 0x32DF09A8,0x50F0,0x5395,{ 0x99,0x23,0x7D,0x44,0xCA,0x71,0xED,0x6D } }; };
template <> struct guid_storage<Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics>{ static constexpr guid value{ 0x2B5FEF71,0x67C9,0x4E5F,{ 0xA3,0x5B,0x41,0x68,0x07,0x11,0xF8,0xC7 } }; };
template <> struct guid_storage<Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics>{ static constexpr guid value{ 0xB3DE8A47,0x83EE,0x4266,{ 0xA9,0x45,0xBE,0xDF,0x50,0x7A,0xFE,0xED } }; };
template <> struct default_interface<Windows::Media::Audio::AudioDeviceInputNode>{ using type = Windows::Media::Audio::IAudioDeviceInputNode; };
template <> struct default_interface<Windows::Media::Audio::AudioDeviceOutputNode>{ using type = Windows::Media::Audio::IAudioDeviceOutputNode; };
template <> struct default_interface<Windows::Media::Audio::AudioFileInputNode>{ using type = Windows::Media::Audio::IAudioFileInputNode; };
template <> struct default_interface<Windows::Media::Audio::AudioFileOutputNode>{ using type = Windows::Media::Audio::IAudioFileOutputNode; };
template <> struct default_interface<Windows::Media::Audio::AudioFrameCompletedEventArgs>{ using type = Windows::Media::Audio::IAudioFrameCompletedEventArgs; };
template <> struct default_interface<Windows::Media::Audio::AudioFrameInputNode>{ using type = Windows::Media::Audio::IAudioFrameInputNode; };
template <> struct default_interface<Windows::Media::Audio::AudioFrameOutputNode>{ using type = Windows::Media::Audio::IAudioFrameOutputNode; };
template <> struct default_interface<Windows::Media::Audio::AudioGraph>{ using type = Windows::Media::Audio::IAudioGraph; };
template <> struct default_interface<Windows::Media::Audio::AudioGraphBatchUpdater>{ using type = Windows::Foundation::IClosable; };
template <> struct default_interface<Windows::Media::Audio::AudioGraphConnection>{ using type = Windows::Media::Audio::IAudioGraphConnection; };
template <> struct default_interface<Windows::Media::Audio::AudioGraphSettings>{ using type = Windows::Media::Audio::IAudioGraphSettings; };
template <> struct default_interface<Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs>{ using type = Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs; };
template <> struct default_interface<Windows::Media::Audio::AudioNodeEmitter>{ using type = Windows::Media::Audio::IAudioNodeEmitter; };
template <> struct default_interface<Windows::Media::Audio::AudioNodeEmitterConeProperties>{ using type = Windows::Media::Audio::IAudioNodeEmitterConeProperties; };
template <> struct default_interface<Windows::Media::Audio::AudioNodeEmitterDecayModel>{ using type = Windows::Media::Audio::IAudioNodeEmitterDecayModel; };
template <> struct default_interface<Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties>{ using type = Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties; };
template <> struct default_interface<Windows::Media::Audio::AudioNodeEmitterShape>{ using type = Windows::Media::Audio::IAudioNodeEmitterShape; };
template <> struct default_interface<Windows::Media::Audio::AudioNodeListener>{ using type = Windows::Media::Audio::IAudioNodeListener; };
template <> struct default_interface<Windows::Media::Audio::AudioStateMonitor>{ using type = Windows::Media::Audio::IAudioStateMonitor; };
template <> struct default_interface<Windows::Media::Audio::AudioSubmixNode>{ using type = Windows::Media::Audio::IAudioInputNode; };
template <> struct default_interface<Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ using type = Windows::Media::Audio::ICreateAudioDeviceInputNodeResult; };
template <> struct default_interface<Windows::Media::Audio::CreateAudioDeviceOutputNodeResult>{ using type = Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult; };
template <> struct default_interface<Windows::Media::Audio::CreateAudioFileInputNodeResult>{ using type = Windows::Media::Audio::ICreateAudioFileInputNodeResult; };
template <> struct default_interface<Windows::Media::Audio::CreateAudioFileOutputNodeResult>{ using type = Windows::Media::Audio::ICreateAudioFileOutputNodeResult; };
template <> struct default_interface<Windows::Media::Audio::CreateAudioGraphResult>{ using type = Windows::Media::Audio::ICreateAudioGraphResult; };
template <> struct default_interface<Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>{ using type = Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult; };
template <> struct default_interface<Windows::Media::Audio::EchoEffectDefinition>{ using type = Windows::Media::Audio::IEchoEffectDefinition; };
template <> struct default_interface<Windows::Media::Audio::EqualizerBand>{ using type = Windows::Media::Audio::IEqualizerBand; };
template <> struct default_interface<Windows::Media::Audio::EqualizerEffectDefinition>{ using type = Windows::Media::Audio::IEqualizerEffectDefinition; };
template <> struct default_interface<Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs>{ using type = Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs; };
template <> struct default_interface<Windows::Media::Audio::LimiterEffectDefinition>{ using type = Windows::Media::Audio::ILimiterEffectDefinition; };
template <> struct default_interface<Windows::Media::Audio::MediaSourceAudioInputNode>{ using type = Windows::Media::Audio::IMediaSourceAudioInputNode; };
template <> struct default_interface<Windows::Media::Audio::ReverbEffectDefinition>{ using type = Windows::Media::Audio::IReverbEffectDefinition; };
template <> struct default_interface<Windows::Media::Audio::SetDefaultSpatialAudioFormatResult>{ using type = Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult; };
template <> struct default_interface<Windows::Media::Audio::SpatialAudioDeviceConfiguration>{ using type = Windows::Media::Audio::ISpatialAudioDeviceConfiguration; };
template <> struct default_interface<Windows::Media::Audio::SpatialAudioFormatConfiguration>{ using type = Windows::Media::Audio::ISpatialAudioFormatConfiguration; };

template <> struct abi<Windows::Media::Audio::IAudioDeviceInputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Device(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioDeviceOutputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Device(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioFileInputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_PlaybackSpeedFactor(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackSpeedFactor(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL Seek(Windows::Foundation::TimeSpan position) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EndTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LoopCount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LoopCount(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourceFile(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_FileCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_FileCompleted(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioFileOutputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_File(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileEncodingProfile(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FinalizeAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioFrameCompletedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Frame(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioFrameInputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_PlaybackSpeedFactor(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackSpeedFactor(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL AddFrame(void* frame) noexcept = 0;
    virtual int32_t WINRT_CALL DiscardQueuedFrames() noexcept = 0;
    virtual int32_t WINRT_CALL get_QueuedSampleCount(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AudioFrameCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AudioFrameCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_QuantumStarted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_QuantumStarted(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioFrameOutputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetFrame(void** audioFrame) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraph>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFrameInputNode(void** frameInputNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFrameInputNodeWithFormat(void* encodingProperties, void** frameInputNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDeviceInputNodeAsync(Windows::Media::Capture::MediaCategory category, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDeviceInputNodeWithFormatAsync(Windows::Media::Capture::MediaCategory category, void* encodingProperties, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDeviceInputNodeWithFormatOnDeviceAsync(Windows::Media::Capture::MediaCategory category, void* encodingProperties, void* device, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFrameOutputNode(void** frameOutputNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFrameOutputNodeWithFormat(void* encodingProperties, void** frameOutputNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDeviceOutputNodeAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFileInputNodeAsync(void* file, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFileOutputNodeAsync(void* file, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFileOutputNodeWithFileProfileAsync(void* file, void* fileEncodingProfile, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSubmixNode(void** submixNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSubmixNodeWithFormat(void* encodingProperties, void** submixNode) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
    virtual int32_t WINRT_CALL ResetAllNodes() noexcept = 0;
    virtual int32_t WINRT_CALL add_QuantumStarted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_QuantumStarted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_QuantumProcessed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_QuantumProcessed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_UnrecoverableErrorOccurred(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UnrecoverableErrorOccurred(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_CompletedQuantumCount(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EncodingProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LatencyInSamples(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrimaryRenderDevice(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RenderDeviceAudioProcessing(Windows::Media::AudioProcessing* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SamplesPerQuantum(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraph2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFrameInputNodeWithFormatAndEmitter(void* encodingProperties, void* emitter, void** frameInputNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDeviceInputNodeWithFormatAndEmitterOnDeviceAsync(Windows::Media::Capture::MediaCategory category, void* encodingProperties, void* device, void* emitter, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFileInputNodeWithEmitterAsync(void* file, void* emitter, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSubmixNodeWithFormatAndEmitter(void* encodingProperties, void* emitter, void** submixNode) noexcept = 0;
    virtual int32_t WINRT_CALL CreateBatchUpdater(void** updater) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraph3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateMediaSourceAudioInputNodeAsync(void* mediaSource, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateMediaSourceAudioInputNodeWithEmitterAsync(void* mediaSource, void* emitter, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraphConnection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Destination(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Gain(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gain(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraphSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EncodingProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EncodingProperties(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrimaryRenderDevice(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PrimaryRenderDevice(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_QuantumSizeSelectionMode(Windows::Media::Audio::QuantumSizeSelectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_QuantumSizeSelectionMode(Windows::Media::Audio::QuantumSizeSelectionMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredSamplesPerQuantum(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredSamplesPerQuantum(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioRenderCategory(Windows::Media::Render::AudioRenderCategory* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AudioRenderCategory(Windows::Media::Render::AudioRenderCategory value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredRenderDeviceAudioProcessing(Windows::Media::AudioProcessing* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredRenderDeviceAudioProcessing(Windows::Media::AudioProcessing value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraphSettings2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_MaxPlaybackSpeedFactor(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPlaybackSpeedFactor(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraphSettingsFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Media::Render::AudioRenderCategory audioRenderCategory, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraphStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAsync(void* settings, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Error(Windows::Media::Audio::AudioGraphUnrecoverableError* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioInputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OutgoingConnections(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL AddOutgoingConnection(void* destination) noexcept = 0;
    virtual int32_t WINRT_CALL AddOutgoingConnectionWithGain(void* destination, double gain) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveOutgoingConnection(void* destination) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioInputNode2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Emitter(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EffectDefinitions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OutgoingGain(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutgoingGain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EncodingProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConsumeInput(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ConsumeInput(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
    virtual int32_t WINRT_CALL Reset() noexcept = 0;
    virtual int32_t WINRT_CALL DisableEffectsByDefinition(void* definition) noexcept = 0;
    virtual int32_t WINRT_CALL EnableEffectsByDefinition(void* definition) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Direction(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Direction(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Shape(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecayModel(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Gain(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DistanceScale(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DistanceScale(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DopplerScale(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DopplerScale(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DopplerVelocity(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DopplerVelocity(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDopplerDisabled(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitter2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SpatialAudioModel(Windows::Media::Audio::SpatialAudioModel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SpatialAudioModel(Windows::Media::Audio::SpatialAudioModel value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterConeProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InnerAngle(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OuterAngle(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OuterAngleGain(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterDecayModel>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::Media::Audio::AudioNodeEmitterDecayKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinGain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxGain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NaturalProperties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateNatural(double minGain, double maxGain, double unityGainDistance, double cutoffDistance, void** decayModel) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCustom(double minGain, double maxGain, void** decayModel) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAudioNodeEmitter(void* shape, void* decayModel, Windows::Media::Audio::AudioNodeEmitterSettings settings, void** emitter) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UnityGainDistance(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CutoffDistance(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterShape>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::Media::Audio::AudioNodeEmitterShapeKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConeProperties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeEmitterShapeStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCone(double innerAngle, double outerAngle, double outerAngleGain, void** shape) noexcept = 0;
    virtual int32_t WINRT_CALL CreateOmnidirectional(void** shape) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeListener>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orientation(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Orientation(Windows::Foundation::Numerics::quaternion value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpeedOfSound(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SpeedOfSound(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DopplerVelocity(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DopplerVelocity(Windows::Foundation::Numerics::float3 value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioNodeWithListener>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Listener(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Listener(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioStateMonitor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SoundLevelChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SoundLevelChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_SoundLevel(Windows::Media::SoundLevel* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IAudioStateMonitorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForRenderMonitoring(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForRenderMonitoringWithCategory(Windows::Media::Render::AudioRenderCategory category, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForRenderMonitoringWithCategoryAndDeviceRole(Windows::Media::Render::AudioRenderCategory category, Windows::Media::Devices::AudioDeviceRole role, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForRenderMonitoringWithCategoryAndDeviceId(Windows::Media::Render::AudioRenderCategory category, void* deviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForCaptureMonitoring(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForCaptureMonitoringWithCategory(Windows::Media::Capture::MediaCategory category, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForCaptureMonitoringWithCategoryAndDeviceRole(Windows::Media::Capture::MediaCategory category, Windows::Media::Devices::AudioDeviceRole role, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForCaptureMonitoringWithCategoryAndDeviceId(Windows::Media::Capture::MediaCategory category, void* deviceId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::AudioDeviceNodeCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInputNode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::AudioDeviceNodeCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceOutputNode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioFileInputNodeResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::AudioFileNodeCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileInputNode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioFileInputNodeResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioFileOutputNodeResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::AudioFileNodeCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileOutputNode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioFileOutputNodeResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioGraphResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::AudioGraphCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Graph(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateAudioGraphResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Node(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IEchoEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_WetDryMix(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WetDryMix(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Feedback(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Feedback(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Delay(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Delay(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IEchoEffectDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* audioGraph, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IEqualizerBand>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Bandwidth(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Bandwidth(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FrequencyCenter(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FrequencyCenter(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Gain(double value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IEqualizerEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Bands(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IEqualizerEffectDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* audioGraph, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequiredSamples(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ILimiterEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Release(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Release(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Loudness(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Loudness(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ILimiterEffectDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* audioGraph, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IMediaSourceAudioInputNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_PlaybackSpeedFactor(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackSpeedFactor(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL Seek(Windows::Foundation::TimeSpan position) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EndTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LoopCount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LoopCount(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaSource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaSourceCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaSourceCompleted(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IReverbEffectDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_WetDryMix(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WetDryMix(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReflectionsDelay(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReflectionsDelay(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReverbDelay(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReverbDelay(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RearDelay(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RearDelay(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PositionLeft(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PositionLeft(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PositionRight(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PositionRight(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PositionMatrixLeft(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PositionMatrixLeft(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PositionMatrixRight(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PositionMatrixRight(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EarlyDiffusion(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EarlyDiffusion(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LateDiffusion(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LateDiffusion(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LowEQGain(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LowEQGain(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LowEQCutoff(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LowEQCutoff(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HighEQGain(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HighEQGain(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HighEQCutoff(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HighEQCutoff(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RoomFilterFreq(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoomFilterFreq(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RoomFilterMain(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoomFilterMain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RoomFilterHF(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoomFilterHF(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReflectionsGain(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReflectionsGain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReverbGain(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReverbGain(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DecayTime(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecayTime(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Density(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Density(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RoomSize(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoomSize(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisableLateField(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisableLateField(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::IReverbEffectDefinitionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* audioGraph, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ISpatialAudioDeviceConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSpatialAudioSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL IsSpatialAudioFormatSupported(void* subtype, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_ActiveSpatialAudioFormat(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DefaultSpatialAudioFormat(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetDefaultSpatialAudioFormatAsync(void* subtype, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_ConfigurationChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ConfigurationChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForDeviceId(void* deviceId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ISpatialAudioFormatConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReportLicenseChangedAsync(void* subtype, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ReportConfigurationChangedAsync(void* subtype, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_MixedRealityExclusiveModePolicy(Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MixedRealityExclusiveModePolicy(Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WindowsSonic(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DolbyAtmosForHeadphones(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DolbyAtmosForHomeTheater(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DolbyAtmosForSpeakers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DTSHeadphoneX(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DTSXUltra(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Audio_IAudioDeviceInputNode
{
    Windows::Devices::Enumeration::DeviceInformation Device() const;
};
template <> struct consume<Windows::Media::Audio::IAudioDeviceInputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioDeviceInputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioDeviceOutputNode
{
    Windows::Devices::Enumeration::DeviceInformation Device() const;
};
template <> struct consume<Windows::Media::Audio::IAudioDeviceOutputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioDeviceOutputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioFileInputNode
{
    void PlaybackSpeedFactor(double value) const;
    double PlaybackSpeedFactor() const;
    Windows::Foundation::TimeSpan Position() const;
    void Seek(Windows::Foundation::TimeSpan const& position) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> StartTime() const;
    void StartTime(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> EndTime() const;
    void EndTime(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<int32_t> LoopCount() const;
    void LoopCount(optional<int32_t> const& value) const;
    Windows::Foundation::TimeSpan Duration() const;
    Windows::Storage::StorageFile SourceFile() const;
    winrt::event_token FileCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioFileInputNode, Windows::Foundation::IInspectable> const& handler) const;
    using FileCompleted_revoker = impl::event_revoker<Windows::Media::Audio::IAudioFileInputNode, &impl::abi_t<Windows::Media::Audio::IAudioFileInputNode>::remove_FileCompleted>;
    FileCompleted_revoker FileCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioFileInputNode, Windows::Foundation::IInspectable> const& handler) const;
    void FileCompleted(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Audio::IAudioFileInputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioFileInputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioFileOutputNode
{
    Windows::Storage::IStorageFile File() const;
    Windows::Media::MediaProperties::MediaEncodingProfile FileEncodingProfile() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Transcoding::TranscodeFailureReason> FinalizeAsync() const;
};
template <> struct consume<Windows::Media::Audio::IAudioFileOutputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioFileOutputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioFrameCompletedEventArgs
{
    Windows::Media::AudioFrame Frame() const;
};
template <> struct consume<Windows::Media::Audio::IAudioFrameCompletedEventArgs> { template <typename D> using type = consume_Windows_Media_Audio_IAudioFrameCompletedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioFrameInputNode
{
    void PlaybackSpeedFactor(double value) const;
    double PlaybackSpeedFactor() const;
    void AddFrame(Windows::Media::AudioFrame const& frame) const;
    void DiscardQueuedFrames() const;
    uint64_t QueuedSampleCount() const;
    winrt::event_token AudioFrameCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioFrameInputNode, Windows::Media::Audio::AudioFrameCompletedEventArgs> const& handler) const;
    using AudioFrameCompleted_revoker = impl::event_revoker<Windows::Media::Audio::IAudioFrameInputNode, &impl::abi_t<Windows::Media::Audio::IAudioFrameInputNode>::remove_AudioFrameCompleted>;
    AudioFrameCompleted_revoker AudioFrameCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioFrameInputNode, Windows::Media::Audio::AudioFrameCompletedEventArgs> const& handler) const;
    void AudioFrameCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token QuantumStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioFrameInputNode, Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs> const& handler) const;
    using QuantumStarted_revoker = impl::event_revoker<Windows::Media::Audio::IAudioFrameInputNode, &impl::abi_t<Windows::Media::Audio::IAudioFrameInputNode>::remove_QuantumStarted>;
    QuantumStarted_revoker QuantumStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioFrameInputNode, Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs> const& handler) const;
    void QuantumStarted(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Audio::IAudioFrameInputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioFrameInputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioFrameOutputNode
{
    Windows::Media::AudioFrame GetFrame() const;
};
template <> struct consume<Windows::Media::Audio::IAudioFrameOutputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioFrameOutputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraph
{
    Windows::Media::Audio::AudioFrameInputNode CreateFrameInputNode() const;
    Windows::Media::Audio::AudioFrameInputNode CreateFrameInputNode(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioDeviceInputNodeResult> CreateDeviceInputNodeAsync(Windows::Media::Capture::MediaCategory const& category) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioDeviceInputNodeResult> CreateDeviceInputNodeAsync(Windows::Media::Capture::MediaCategory const& category, Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioDeviceInputNodeResult> CreateDeviceInputNodeAsync(Windows::Media::Capture::MediaCategory const& category, Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, Windows::Devices::Enumeration::DeviceInformation const& device) const;
    Windows::Media::Audio::AudioFrameOutputNode CreateFrameOutputNode() const;
    Windows::Media::Audio::AudioFrameOutputNode CreateFrameOutputNode(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioDeviceOutputNodeResult> CreateDeviceOutputNodeAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioFileInputNodeResult> CreateFileInputNodeAsync(Windows::Storage::IStorageFile const& file) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioFileOutputNodeResult> CreateFileOutputNodeAsync(Windows::Storage::IStorageFile const& file) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioFileOutputNodeResult> CreateFileOutputNodeAsync(Windows::Storage::IStorageFile const& file, Windows::Media::MediaProperties::MediaEncodingProfile const& fileEncodingProfile) const;
    Windows::Media::Audio::AudioSubmixNode CreateSubmixNode() const;
    Windows::Media::Audio::AudioSubmixNode CreateSubmixNode(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const;
    void Start() const;
    void Stop() const;
    void ResetAllNodes() const;
    winrt::event_token QuantumStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioGraph, Windows::Foundation::IInspectable> const& handler) const;
    using QuantumStarted_revoker = impl::event_revoker<Windows::Media::Audio::IAudioGraph, &impl::abi_t<Windows::Media::Audio::IAudioGraph>::remove_QuantumStarted>;
    QuantumStarted_revoker QuantumStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioGraph, Windows::Foundation::IInspectable> const& handler) const;
    void QuantumStarted(winrt::event_token const& token) const noexcept;
    winrt::event_token QuantumProcessed(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioGraph, Windows::Foundation::IInspectable> const& handler) const;
    using QuantumProcessed_revoker = impl::event_revoker<Windows::Media::Audio::IAudioGraph, &impl::abi_t<Windows::Media::Audio::IAudioGraph>::remove_QuantumProcessed>;
    QuantumProcessed_revoker QuantumProcessed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioGraph, Windows::Foundation::IInspectable> const& handler) const;
    void QuantumProcessed(winrt::event_token const& token) const noexcept;
    winrt::event_token UnrecoverableErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioGraph, Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs> const& handler) const;
    using UnrecoverableErrorOccurred_revoker = impl::event_revoker<Windows::Media::Audio::IAudioGraph, &impl::abi_t<Windows::Media::Audio::IAudioGraph>::remove_UnrecoverableErrorOccurred>;
    UnrecoverableErrorOccurred_revoker UnrecoverableErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioGraph, Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs> const& handler) const;
    void UnrecoverableErrorOccurred(winrt::event_token const& token) const noexcept;
    uint64_t CompletedQuantumCount() const;
    Windows::Media::MediaProperties::AudioEncodingProperties EncodingProperties() const;
    int32_t LatencyInSamples() const;
    Windows::Devices::Enumeration::DeviceInformation PrimaryRenderDevice() const;
    Windows::Media::AudioProcessing RenderDeviceAudioProcessing() const;
    int32_t SamplesPerQuantum() const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraph> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraph<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraph2
{
    Windows::Media::Audio::AudioFrameInputNode CreateFrameInputNode(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, Windows::Media::Audio::AudioNodeEmitter const& emitter) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioDeviceInputNodeResult> CreateDeviceInputNodeAsync(Windows::Media::Capture::MediaCategory const& category, Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, Windows::Devices::Enumeration::DeviceInformation const& device, Windows::Media::Audio::AudioNodeEmitter const& emitter) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioFileInputNodeResult> CreateFileInputNodeAsync(Windows::Storage::IStorageFile const& file, Windows::Media::Audio::AudioNodeEmitter const& emitter) const;
    Windows::Media::Audio::AudioSubmixNode CreateSubmixNode(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, Windows::Media::Audio::AudioNodeEmitter const& emitter) const;
    Windows::Media::Audio::AudioGraphBatchUpdater CreateBatchUpdater() const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraph2> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraph2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraph3
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult> CreateMediaSourceAudioInputNodeAsync(Windows::Media::Core::MediaSource const& mediaSource) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult> CreateMediaSourceAudioInputNodeAsync(Windows::Media::Core::MediaSource const& mediaSource, Windows::Media::Audio::AudioNodeEmitter const& emitter) const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraph3> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraph3<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraphConnection
{
    Windows::Media::Audio::IAudioNode Destination() const;
    void Gain(double value) const;
    double Gain() const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraphConnection> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraphConnection<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraphSettings
{
    Windows::Media::MediaProperties::AudioEncodingProperties EncodingProperties() const;
    void EncodingProperties(Windows::Media::MediaProperties::AudioEncodingProperties const& value) const;
    Windows::Devices::Enumeration::DeviceInformation PrimaryRenderDevice() const;
    void PrimaryRenderDevice(Windows::Devices::Enumeration::DeviceInformation const& value) const;
    Windows::Media::Audio::QuantumSizeSelectionMode QuantumSizeSelectionMode() const;
    void QuantumSizeSelectionMode(Windows::Media::Audio::QuantumSizeSelectionMode const& value) const;
    int32_t DesiredSamplesPerQuantum() const;
    void DesiredSamplesPerQuantum(int32_t value) const;
    Windows::Media::Render::AudioRenderCategory AudioRenderCategory() const;
    void AudioRenderCategory(Windows::Media::Render::AudioRenderCategory const& value) const;
    Windows::Media::AudioProcessing DesiredRenderDeviceAudioProcessing() const;
    void DesiredRenderDeviceAudioProcessing(Windows::Media::AudioProcessing const& value) const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraphSettings> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraphSettings<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraphSettings2
{
    void MaxPlaybackSpeedFactor(double value) const;
    double MaxPlaybackSpeedFactor() const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraphSettings2> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraphSettings2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraphSettingsFactory
{
    Windows::Media::Audio::AudioGraphSettings Create(Windows::Media::Render::AudioRenderCategory const& audioRenderCategory) const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraphSettingsFactory> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraphSettingsFactory<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraphStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::CreateAudioGraphResult> CreateAsync(Windows::Media::Audio::AudioGraphSettings const& settings) const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraphStatics> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraphStatics<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioGraphUnrecoverableErrorOccurredEventArgs
{
    Windows::Media::Audio::AudioGraphUnrecoverableError Error() const;
};
template <> struct consume<Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs> { template <typename D> using type = consume_Windows_Media_Audio_IAudioGraphUnrecoverableErrorOccurredEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioInputNode
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Audio::AudioGraphConnection> OutgoingConnections() const;
    void AddOutgoingConnection(Windows::Media::Audio::IAudioNode const& destination) const;
    void AddOutgoingConnection(Windows::Media::Audio::IAudioNode const& destination, double gain) const;
    void RemoveOutgoingConnection(Windows::Media::Audio::IAudioNode const& destination) const;
};
template <> struct consume<Windows::Media::Audio::IAudioInputNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioInputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioInputNode2
{
    Windows::Media::Audio::AudioNodeEmitter Emitter() const;
};
template <> struct consume<Windows::Media::Audio::IAudioInputNode2> { template <typename D> using type = consume_Windows_Media_Audio_IAudioInputNode2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNode
{
    Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition> EffectDefinitions() const;
    void OutgoingGain(double value) const;
    double OutgoingGain() const;
    Windows::Media::MediaProperties::AudioEncodingProperties EncodingProperties() const;
    bool ConsumeInput() const;
    void ConsumeInput(bool value) const;
    void Start() const;
    void Stop() const;
    void Reset() const;
    void DisableEffectsByDefinition(Windows::Media::Effects::IAudioEffectDefinition const& definition) const;
    void EnableEffectsByDefinition(Windows::Media::Effects::IAudioEffectDefinition const& definition) const;
};
template <> struct consume<Windows::Media::Audio::IAudioNode> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitter
{
    Windows::Foundation::Numerics::float3 Position() const;
    void Position(Windows::Foundation::Numerics::float3 const& value) const;
    Windows::Foundation::Numerics::float3 Direction() const;
    void Direction(Windows::Foundation::Numerics::float3 const& value) const;
    Windows::Media::Audio::AudioNodeEmitterShape Shape() const;
    Windows::Media::Audio::AudioNodeEmitterDecayModel DecayModel() const;
    double Gain() const;
    void Gain(double value) const;
    double DistanceScale() const;
    void DistanceScale(double value) const;
    double DopplerScale() const;
    void DopplerScale(double value) const;
    Windows::Foundation::Numerics::float3 DopplerVelocity() const;
    void DopplerVelocity(Windows::Foundation::Numerics::float3 const& value) const;
    bool IsDopplerDisabled() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitter> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitter<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitter2
{
    Windows::Media::Audio::SpatialAudioModel SpatialAudioModel() const;
    void SpatialAudioModel(Windows::Media::Audio::SpatialAudioModel const& value) const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitter2> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitter2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterConeProperties
{
    double InnerAngle() const;
    double OuterAngle() const;
    double OuterAngleGain() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterConeProperties> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterConeProperties<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterDecayModel
{
    Windows::Media::Audio::AudioNodeEmitterDecayKind Kind() const;
    double MinGain() const;
    double MaxGain() const;
    Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties NaturalProperties() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterDecayModel> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterDecayModel<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterDecayModelStatics
{
    Windows::Media::Audio::AudioNodeEmitterDecayModel CreateNatural(double minGain, double maxGain, double unityGainDistance, double cutoffDistance) const;
    Windows::Media::Audio::AudioNodeEmitterDecayModel CreateCustom(double minGain, double maxGain) const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterDecayModelStatics<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterFactory
{
    Windows::Media::Audio::AudioNodeEmitter CreateAudioNodeEmitter(Windows::Media::Audio::AudioNodeEmitterShape const& shape, Windows::Media::Audio::AudioNodeEmitterDecayModel const& decayModel, Windows::Media::Audio::AudioNodeEmitterSettings const& settings) const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterFactory> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterFactory<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterNaturalDecayModelProperties
{
    double UnityGainDistance() const;
    double CutoffDistance() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterNaturalDecayModelProperties<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterShape
{
    Windows::Media::Audio::AudioNodeEmitterShapeKind Kind() const;
    Windows::Media::Audio::AudioNodeEmitterConeProperties ConeProperties() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterShape> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterShape<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeEmitterShapeStatics
{
    Windows::Media::Audio::AudioNodeEmitterShape CreateCone(double innerAngle, double outerAngle, double outerAngleGain) const;
    Windows::Media::Audio::AudioNodeEmitterShape CreateOmnidirectional() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeEmitterShapeStatics> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeEmitterShapeStatics<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeListener
{
    Windows::Foundation::Numerics::float3 Position() const;
    void Position(Windows::Foundation::Numerics::float3 const& value) const;
    Windows::Foundation::Numerics::quaternion Orientation() const;
    void Orientation(Windows::Foundation::Numerics::quaternion const& value) const;
    double SpeedOfSound() const;
    void SpeedOfSound(double value) const;
    Windows::Foundation::Numerics::float3 DopplerVelocity() const;
    void DopplerVelocity(Windows::Foundation::Numerics::float3 const& value) const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeListener> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeListener<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioNodeWithListener
{
    void Listener(Windows::Media::Audio::AudioNodeListener const& value) const;
    Windows::Media::Audio::AudioNodeListener Listener() const;
};
template <> struct consume<Windows::Media::Audio::IAudioNodeWithListener> { template <typename D> using type = consume_Windows_Media_Audio_IAudioNodeWithListener<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioStateMonitor
{
    winrt::event_token SoundLevelChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioStateMonitor, Windows::Foundation::IInspectable> const& handler) const;
    using SoundLevelChanged_revoker = impl::event_revoker<Windows::Media::Audio::IAudioStateMonitor, &impl::abi_t<Windows::Media::Audio::IAudioStateMonitor>::remove_SoundLevelChanged>;
    SoundLevelChanged_revoker SoundLevelChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::AudioStateMonitor, Windows::Foundation::IInspectable> const& handler) const;
    void SoundLevelChanged(winrt::event_token const& token) const noexcept;
    Windows::Media::SoundLevel SoundLevel() const;
};
template <> struct consume<Windows::Media::Audio::IAudioStateMonitor> { template <typename D> using type = consume_Windows_Media_Audio_IAudioStateMonitor<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IAudioStateMonitorStatics
{
    Windows::Media::Audio::AudioStateMonitor CreateForRenderMonitoring() const;
    Windows::Media::Audio::AudioStateMonitor CreateForRenderMonitoring(Windows::Media::Render::AudioRenderCategory const& category) const;
    Windows::Media::Audio::AudioStateMonitor CreateForRenderMonitoring(Windows::Media::Render::AudioRenderCategory const& category, Windows::Media::Devices::AudioDeviceRole const& role) const;
    Windows::Media::Audio::AudioStateMonitor CreateForRenderMonitoringWithCategoryAndDeviceId(Windows::Media::Render::AudioRenderCategory const& category, param::hstring const& deviceId) const;
    Windows::Media::Audio::AudioStateMonitor CreateForCaptureMonitoring() const;
    Windows::Media::Audio::AudioStateMonitor CreateForCaptureMonitoring(Windows::Media::Capture::MediaCategory const& category) const;
    Windows::Media::Audio::AudioStateMonitor CreateForCaptureMonitoring(Windows::Media::Capture::MediaCategory const& category, Windows::Media::Devices::AudioDeviceRole const& role) const;
    Windows::Media::Audio::AudioStateMonitor CreateForCaptureMonitoringWithCategoryAndDeviceId(Windows::Media::Capture::MediaCategory const& category, param::hstring const& deviceId) const;
};
template <> struct consume<Windows::Media::Audio::IAudioStateMonitorStatics> { template <typename D> using type = consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult
{
    Windows::Media::Audio::AudioDeviceNodeCreationStatus Status() const;
    Windows::Media::Audio::AudioDeviceInputNode DeviceInputNode() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult
{
    Windows::Media::Audio::AudioDeviceNodeCreationStatus Status() const;
    Windows::Media::Audio::AudioDeviceOutputNode DeviceOutputNode() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult
{
    Windows::Media::Audio::AudioFileNodeCreationStatus Status() const;
    Windows::Media::Audio::AudioFileInputNode FileInputNode() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioFileInputNodeResult> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioFileInputNodeResult2> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult
{
    Windows::Media::Audio::AudioFileNodeCreationStatus Status() const;
    Windows::Media::Audio::AudioFileOutputNode FileOutputNode() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioFileOutputNodeResult> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioFileOutputNodeResult2> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioGraphResult
{
    Windows::Media::Audio::AudioGraphCreationStatus Status() const;
    Windows::Media::Audio::AudioGraph Graph() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioGraphResult> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioGraphResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateAudioGraphResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Audio::ICreateAudioGraphResult2> { template <typename D> using type = consume_Windows_Media_Audio_ICreateAudioGraphResult2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult
{
    Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus Status() const;
    Windows::Media::Audio::MediaSourceAudioInputNode Node() const;
};
template <> struct consume<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult> { template <typename D> using type = consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2> { template <typename D> using type = consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult2<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IEchoEffectDefinition
{
    void WetDryMix(double value) const;
    double WetDryMix() const;
    void Feedback(double value) const;
    double Feedback() const;
    void Delay(double value) const;
    double Delay() const;
};
template <> struct consume<Windows::Media::Audio::IEchoEffectDefinition> { template <typename D> using type = consume_Windows_Media_Audio_IEchoEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IEchoEffectDefinitionFactory
{
    Windows::Media::Audio::EchoEffectDefinition Create(Windows::Media::Audio::AudioGraph const& audioGraph) const;
};
template <> struct consume<Windows::Media::Audio::IEchoEffectDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Audio_IEchoEffectDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IEqualizerBand
{
    double Bandwidth() const;
    void Bandwidth(double value) const;
    double FrequencyCenter() const;
    void FrequencyCenter(double value) const;
    double Gain() const;
    void Gain(double value) const;
};
template <> struct consume<Windows::Media::Audio::IEqualizerBand> { template <typename D> using type = consume_Windows_Media_Audio_IEqualizerBand<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IEqualizerEffectDefinition
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Audio::EqualizerBand> Bands() const;
};
template <> struct consume<Windows::Media::Audio::IEqualizerEffectDefinition> { template <typename D> using type = consume_Windows_Media_Audio_IEqualizerEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IEqualizerEffectDefinitionFactory
{
    Windows::Media::Audio::EqualizerEffectDefinition Create(Windows::Media::Audio::AudioGraph const& audioGraph) const;
};
template <> struct consume<Windows::Media::Audio::IEqualizerEffectDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Audio_IEqualizerEffectDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IFrameInputNodeQuantumStartedEventArgs
{
    int32_t RequiredSamples() const;
};
template <> struct consume<Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs> { template <typename D> using type = consume_Windows_Media_Audio_IFrameInputNodeQuantumStartedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ILimiterEffectDefinition
{
    void Release(uint32_t value) const;
    uint32_t Release() const;
    void Loudness(uint32_t value) const;
    uint32_t Loudness() const;
};
template <> struct consume<Windows::Media::Audio::ILimiterEffectDefinition> { template <typename D> using type = consume_Windows_Media_Audio_ILimiterEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ILimiterEffectDefinitionFactory
{
    Windows::Media::Audio::LimiterEffectDefinition Create(Windows::Media::Audio::AudioGraph const& audioGraph) const;
};
template <> struct consume<Windows::Media::Audio::ILimiterEffectDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Audio_ILimiterEffectDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IMediaSourceAudioInputNode
{
    void PlaybackSpeedFactor(double value) const;
    double PlaybackSpeedFactor() const;
    Windows::Foundation::TimeSpan Position() const;
    void Seek(Windows::Foundation::TimeSpan const& position) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> StartTime() const;
    void StartTime(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> EndTime() const;
    void EndTime(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<int32_t> LoopCount() const;
    void LoopCount(optional<int32_t> const& value) const;
    Windows::Foundation::TimeSpan Duration() const;
    Windows::Media::Core::MediaSource MediaSource() const;
    winrt::event_token MediaSourceCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::MediaSourceAudioInputNode, Windows::Foundation::IInspectable> const& handler) const;
    using MediaSourceCompleted_revoker = impl::event_revoker<Windows::Media::Audio::IMediaSourceAudioInputNode, &impl::abi_t<Windows::Media::Audio::IMediaSourceAudioInputNode>::remove_MediaSourceCompleted>;
    MediaSourceCompleted_revoker MediaSourceCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::MediaSourceAudioInputNode, Windows::Foundation::IInspectable> const& handler) const;
    void MediaSourceCompleted(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Audio::IMediaSourceAudioInputNode> { template <typename D> using type = consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IReverbEffectDefinition
{
    void WetDryMix(double value) const;
    double WetDryMix() const;
    void ReflectionsDelay(uint32_t value) const;
    uint32_t ReflectionsDelay() const;
    void ReverbDelay(uint8_t value) const;
    uint8_t ReverbDelay() const;
    void RearDelay(uint8_t value) const;
    uint8_t RearDelay() const;
    void PositionLeft(uint8_t value) const;
    uint8_t PositionLeft() const;
    void PositionRight(uint8_t value) const;
    uint8_t PositionRight() const;
    void PositionMatrixLeft(uint8_t value) const;
    uint8_t PositionMatrixLeft() const;
    void PositionMatrixRight(uint8_t value) const;
    uint8_t PositionMatrixRight() const;
    void EarlyDiffusion(uint8_t value) const;
    uint8_t EarlyDiffusion() const;
    void LateDiffusion(uint8_t value) const;
    uint8_t LateDiffusion() const;
    void LowEQGain(uint8_t value) const;
    uint8_t LowEQGain() const;
    void LowEQCutoff(uint8_t value) const;
    uint8_t LowEQCutoff() const;
    void HighEQGain(uint8_t value) const;
    uint8_t HighEQGain() const;
    void HighEQCutoff(uint8_t value) const;
    uint8_t HighEQCutoff() const;
    void RoomFilterFreq(double value) const;
    double RoomFilterFreq() const;
    void RoomFilterMain(double value) const;
    double RoomFilterMain() const;
    void RoomFilterHF(double value) const;
    double RoomFilterHF() const;
    void ReflectionsGain(double value) const;
    double ReflectionsGain() const;
    void ReverbGain(double value) const;
    double ReverbGain() const;
    void DecayTime(double value) const;
    double DecayTime() const;
    void Density(double value) const;
    double Density() const;
    void RoomSize(double value) const;
    double RoomSize() const;
    void DisableLateField(bool value) const;
    bool DisableLateField() const;
};
template <> struct consume<Windows::Media::Audio::IReverbEffectDefinition> { template <typename D> using type = consume_Windows_Media_Audio_IReverbEffectDefinition<D>; };

template <typename D>
struct consume_Windows_Media_Audio_IReverbEffectDefinitionFactory
{
    Windows::Media::Audio::ReverbEffectDefinition Create(Windows::Media::Audio::AudioGraph const& audioGraph) const;
};
template <> struct consume<Windows::Media::Audio::IReverbEffectDefinitionFactory> { template <typename D> using type = consume_Windows_Media_Audio_IReverbEffectDefinitionFactory<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ISetDefaultSpatialAudioFormatResult
{
    Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus Status() const;
};
template <> struct consume<Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult> { template <typename D> using type = consume_Windows_Media_Audio_ISetDefaultSpatialAudioFormatResult<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration
{
    hstring DeviceId() const;
    bool IsSpatialAudioSupported() const;
    bool IsSpatialAudioFormatSupported(param::hstring const& subtype) const;
    hstring ActiveSpatialAudioFormat() const;
    hstring DefaultSpatialAudioFormat() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Audio::SetDefaultSpatialAudioFormatResult> SetDefaultSpatialAudioFormatAsync(param::hstring const& subtype) const;
    winrt::event_token ConfigurationChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Audio::SpatialAudioDeviceConfiguration, Windows::Foundation::IInspectable> const& handler) const;
    using ConfigurationChanged_revoker = impl::event_revoker<Windows::Media::Audio::ISpatialAudioDeviceConfiguration, &impl::abi_t<Windows::Media::Audio::ISpatialAudioDeviceConfiguration>::remove_ConfigurationChanged>;
    ConfigurationChanged_revoker ConfigurationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Audio::SpatialAudioDeviceConfiguration, Windows::Foundation::IInspectable> const& handler) const;
    void ConfigurationChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Audio::ISpatialAudioDeviceConfiguration> { template <typename D> using type = consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ISpatialAudioDeviceConfigurationStatics
{
    Windows::Media::Audio::SpatialAudioDeviceConfiguration GetForDeviceId(param::hstring const& deviceId) const;
};
template <> struct consume<Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics> { template <typename D> using type = consume_Windows_Media_Audio_ISpatialAudioDeviceConfigurationStatics<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ISpatialAudioFormatConfiguration
{
    Windows::Foundation::IAsyncAction ReportLicenseChangedAsync(param::hstring const& subtype) const;
    Windows::Foundation::IAsyncAction ReportConfigurationChangedAsync(param::hstring const& subtype) const;
    Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy MixedRealityExclusiveModePolicy() const;
    void MixedRealityExclusiveModePolicy(Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy const& value) const;
};
template <> struct consume<Windows::Media::Audio::ISpatialAudioFormatConfiguration> { template <typename D> using type = consume_Windows_Media_Audio_ISpatialAudioFormatConfiguration<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ISpatialAudioFormatConfigurationStatics
{
    Windows::Media::Audio::SpatialAudioFormatConfiguration GetDefault() const;
};
template <> struct consume<Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics> { template <typename D> using type = consume_Windows_Media_Audio_ISpatialAudioFormatConfigurationStatics<D>; };

template <typename D>
struct consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics
{
    hstring WindowsSonic() const;
    hstring DolbyAtmosForHeadphones() const;
    hstring DolbyAtmosForHomeTheater() const;
    hstring DolbyAtmosForSpeakers() const;
    hstring DTSHeadphoneX() const;
    hstring DTSXUltra() const;
};
template <> struct consume<Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics> { template <typename D> using type = consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>; };

}
