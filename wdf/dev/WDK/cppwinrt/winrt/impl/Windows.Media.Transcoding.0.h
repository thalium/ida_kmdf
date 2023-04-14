// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Media::Core {

struct IMediaSource;

}

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

struct MediaEncodingProfile;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::Media::Transcoding {

enum class MediaVideoProcessingAlgorithm : int32_t
{
    Default = 0,
    MrfCrf444 = 1,
};

enum class TranscodeFailureReason : int32_t
{
    None = 0,
    Unknown = 1,
    InvalidProfile = 2,
    CodecNotFound = 3,
};

struct IMediaTranscoder;
struct IMediaTranscoder2;
struct IPrepareTranscodeResult;
struct MediaTranscoder;
struct PrepareTranscodeResult;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Transcoding::IMediaTranscoder>{ using type = interface_category; };
template <> struct category<Windows::Media::Transcoding::IMediaTranscoder2>{ using type = interface_category; };
template <> struct category<Windows::Media::Transcoding::IPrepareTranscodeResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Transcoding::MediaTranscoder>{ using type = class_category; };
template <> struct category<Windows::Media::Transcoding::PrepareTranscodeResult>{ using type = class_category; };
template <> struct category<Windows::Media::Transcoding::MediaVideoProcessingAlgorithm>{ using type = enum_category; };
template <> struct category<Windows::Media::Transcoding::TranscodeFailureReason>{ using type = enum_category; };
template <> struct name<Windows::Media::Transcoding::IMediaTranscoder>{ static constexpr auto & value{ L"Windows.Media.Transcoding.IMediaTranscoder" }; };
template <> struct name<Windows::Media::Transcoding::IMediaTranscoder2>{ static constexpr auto & value{ L"Windows.Media.Transcoding.IMediaTranscoder2" }; };
template <> struct name<Windows::Media::Transcoding::IPrepareTranscodeResult>{ static constexpr auto & value{ L"Windows.Media.Transcoding.IPrepareTranscodeResult" }; };
template <> struct name<Windows::Media::Transcoding::MediaTranscoder>{ static constexpr auto & value{ L"Windows.Media.Transcoding.MediaTranscoder" }; };
template <> struct name<Windows::Media::Transcoding::PrepareTranscodeResult>{ static constexpr auto & value{ L"Windows.Media.Transcoding.PrepareTranscodeResult" }; };
template <> struct name<Windows::Media::Transcoding::MediaVideoProcessingAlgorithm>{ static constexpr auto & value{ L"Windows.Media.Transcoding.MediaVideoProcessingAlgorithm" }; };
template <> struct name<Windows::Media::Transcoding::TranscodeFailureReason>{ static constexpr auto & value{ L"Windows.Media.Transcoding.TranscodeFailureReason" }; };
template <> struct guid_storage<Windows::Media::Transcoding::IMediaTranscoder>{ static constexpr guid value{ 0x190C99D2,0xA0AA,0x4D34,{ 0x86,0xBC,0xEE,0xD1,0xB1,0x2C,0x2F,0x5B } }; };
template <> struct guid_storage<Windows::Media::Transcoding::IMediaTranscoder2>{ static constexpr guid value{ 0x40531D74,0x35E0,0x4F04,{ 0x85,0x74,0xCA,0x8B,0xC4,0xE5,0xA0,0x82 } }; };
template <> struct guid_storage<Windows::Media::Transcoding::IPrepareTranscodeResult>{ static constexpr guid value{ 0x05F25DCE,0x994F,0x4A34,{ 0x9D,0x68,0x97,0xCC,0xCE,0x17,0x30,0xD6 } }; };
template <> struct default_interface<Windows::Media::Transcoding::MediaTranscoder>{ using type = Windows::Media::Transcoding::IMediaTranscoder; };
template <> struct default_interface<Windows::Media::Transcoding::PrepareTranscodeResult>{ using type = Windows::Media::Transcoding::IPrepareTranscodeResult; };

template <> struct abi<Windows::Media::Transcoding::IMediaTranscoder>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_TrimStartTime(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrimStartTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TrimStopTime(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrimStopTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlwaysReencode(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlwaysReencode(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HardwareAccelerationEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareAccelerationEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL AddAudioEffect(void* activatableClassId) noexcept = 0;
    virtual int32_t WINRT_CALL AddAudioEffectWithSettings(void* activatableClassId, bool effectRequired, void* configuration) noexcept = 0;
    virtual int32_t WINRT_CALL AddVideoEffect(void* activatableClassId) noexcept = 0;
    virtual int32_t WINRT_CALL AddVideoEffectWithSettings(void* activatableClassId, bool effectRequired, void* configuration) noexcept = 0;
    virtual int32_t WINRT_CALL ClearEffects() noexcept = 0;
    virtual int32_t WINRT_CALL PrepareFileTranscodeAsync(void* source, void* destination, void* profile, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PrepareStreamTranscodeAsync(void* source, void* destination, void* profile, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Transcoding::IMediaTranscoder2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL PrepareMediaStreamSourceTranscodeAsync(void* source, void* destination, void* profile, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL put_VideoProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Transcoding::IPrepareTranscodeResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanTranscode(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FailureReason(Windows::Media::Transcoding::TranscodeFailureReason* value) noexcept = 0;
    virtual int32_t WINRT_CALL TranscodeAsync(void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Transcoding_IMediaTranscoder
{
    void TrimStartTime(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan TrimStartTime() const;
    void TrimStopTime(Windows::Foundation::TimeSpan const& value) const;
    Windows::Foundation::TimeSpan TrimStopTime() const;
    void AlwaysReencode(bool value) const;
    bool AlwaysReencode() const;
    void HardwareAccelerationEnabled(bool value) const;
    bool HardwareAccelerationEnabled() const;
    void AddAudioEffect(param::hstring const& activatableClassId) const;
    void AddAudioEffect(param::hstring const& activatableClassId, bool effectRequired, Windows::Foundation::Collections::IPropertySet const& configuration) const;
    void AddVideoEffect(param::hstring const& activatableClassId) const;
    void AddVideoEffect(param::hstring const& activatableClassId, bool effectRequired, Windows::Foundation::Collections::IPropertySet const& configuration) const;
    void ClearEffects() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Transcoding::PrepareTranscodeResult> PrepareFileTranscodeAsync(Windows::Storage::IStorageFile const& source, Windows::Storage::IStorageFile const& destination, Windows::Media::MediaProperties::MediaEncodingProfile const& profile) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Transcoding::PrepareTranscodeResult> PrepareStreamTranscodeAsync(Windows::Storage::Streams::IRandomAccessStream const& source, Windows::Storage::Streams::IRandomAccessStream const& destination, Windows::Media::MediaProperties::MediaEncodingProfile const& profile) const;
};
template <> struct consume<Windows::Media::Transcoding::IMediaTranscoder> { template <typename D> using type = consume_Windows_Media_Transcoding_IMediaTranscoder<D>; };

template <typename D>
struct consume_Windows_Media_Transcoding_IMediaTranscoder2
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Transcoding::PrepareTranscodeResult> PrepareMediaStreamSourceTranscodeAsync(Windows::Media::Core::IMediaSource const& source, Windows::Storage::Streams::IRandomAccessStream const& destination, Windows::Media::MediaProperties::MediaEncodingProfile const& profile) const;
    void VideoProcessingAlgorithm(Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const& value) const;
    Windows::Media::Transcoding::MediaVideoProcessingAlgorithm VideoProcessingAlgorithm() const;
};
template <> struct consume<Windows::Media::Transcoding::IMediaTranscoder2> { template <typename D> using type = consume_Windows_Media_Transcoding_IMediaTranscoder2<D>; };

template <typename D>
struct consume_Windows_Media_Transcoding_IPrepareTranscodeResult
{
    bool CanTranscode() const;
    Windows::Media::Transcoding::TranscodeFailureReason FailureReason() const;
    Windows::Foundation::IAsyncActionWithProgress<double> TranscodeAsync() const;
};
template <> struct consume<Windows::Media::Transcoding::IPrepareTranscodeResult> { template <typename D> using type = consume_Windows_Media_Transcoding_IPrepareTranscodeResult<D>; };

}
