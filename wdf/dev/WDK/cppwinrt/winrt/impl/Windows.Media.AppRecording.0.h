// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage {

struct StorageFile;
struct StorageFolder;

}

WINRT_EXPORT namespace winrt::Windows::Media::AppRecording {

enum class AppRecordingSaveScreenshotOption : int32_t
{
    None = 0,
    HdrContentVisible = 1,
};

struct IAppRecordingManager;
struct IAppRecordingManagerStatics;
struct IAppRecordingResult;
struct IAppRecordingSaveScreenshotResult;
struct IAppRecordingSavedScreenshotInfo;
struct IAppRecordingStatus;
struct IAppRecordingStatusDetails;
struct AppRecordingManager;
struct AppRecordingResult;
struct AppRecordingSaveScreenshotResult;
struct AppRecordingSavedScreenshotInfo;
struct AppRecordingStatus;
struct AppRecordingStatusDetails;

}

namespace winrt::impl {

template <> struct category<Windows::Media::AppRecording::IAppRecordingManager>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::IAppRecordingManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::IAppRecordingResult>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::IAppRecordingStatus>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::IAppRecordingStatusDetails>{ using type = interface_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingManager>{ using type = class_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingResult>{ using type = class_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult>{ using type = class_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo>{ using type = class_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingStatus>{ using type = class_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingStatusDetails>{ using type = class_category; };
template <> struct category<Windows::Media::AppRecording::AppRecordingSaveScreenshotOption>{ using type = enum_category; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingManager>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingManager" }; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingManagerStatics>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingManagerStatics" }; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingResult>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingResult" }; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingSaveScreenshotResult" }; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingSavedScreenshotInfo" }; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingStatus>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingStatus" }; };
template <> struct name<Windows::Media::AppRecording::IAppRecordingStatusDetails>{ static constexpr auto & value{ L"Windows.Media.AppRecording.IAppRecordingStatusDetails" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingManager>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingManager" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingResult>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingResult" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingSaveScreenshotResult" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingSavedScreenshotInfo" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingStatus>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingStatus" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingStatusDetails>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingStatusDetails" }; };
template <> struct name<Windows::Media::AppRecording::AppRecordingSaveScreenshotOption>{ static constexpr auto & value{ L"Windows.Media.AppRecording.AppRecordingSaveScreenshotOption" }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingManager>{ static constexpr guid value{ 0xE7E26076,0xA044,0x48E2,{ 0xA5,0x12,0x30,0x94,0xD5,0x74,0xC7,0xCC } }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingManagerStatics>{ static constexpr guid value{ 0x50E709F7,0x38CE,0x4BD3,{ 0x9D,0xB2,0xE7,0x2B,0xBE,0x9D,0xE1,0x1D } }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingResult>{ static constexpr guid value{ 0x3A900864,0xC66D,0x46F9,{ 0xB2,0xD9,0x5B,0xC2,0xDA,0xD0,0x70,0xD7 } }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult>{ static constexpr guid value{ 0x9C5B8D0A,0x0ABB,0x4457,{ 0xAA,0xEE,0x24,0xF9,0xC1,0x2E,0xC7,0x78 } }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo>{ static constexpr guid value{ 0x9B642D0A,0x189A,0x4D00,{ 0xBF,0x25,0xE1,0xBB,0x12,0x49,0xD5,0x94 } }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingStatus>{ static constexpr guid value{ 0x1D0CC82C,0xBC18,0x4B8A,{ 0xA6,0xEF,0x12,0x7E,0xFA,0xB3,0xB5,0xD9 } }; };
template <> struct guid_storage<Windows::Media::AppRecording::IAppRecordingStatusDetails>{ static constexpr guid value{ 0xB538A9B0,0x14ED,0x4412,{ 0xAC,0x45,0x6D,0x67,0x2C,0x9C,0x99,0x49 } }; };
template <> struct default_interface<Windows::Media::AppRecording::AppRecordingManager>{ using type = Windows::Media::AppRecording::IAppRecordingManager; };
template <> struct default_interface<Windows::Media::AppRecording::AppRecordingResult>{ using type = Windows::Media::AppRecording::IAppRecordingResult; };
template <> struct default_interface<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult>{ using type = Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult; };
template <> struct default_interface<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo>{ using type = Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo; };
template <> struct default_interface<Windows::Media::AppRecording::AppRecordingStatus>{ using type = Windows::Media::AppRecording::IAppRecordingStatus; };
template <> struct default_interface<Windows::Media::AppRecording::AppRecordingStatusDetails>{ using type = Windows::Media::AppRecording::IAppRecordingStatusDetails; };

template <> struct abi<Windows::Media::AppRecording::IAppRecordingManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetStatus(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL StartRecordingToFileAsync(void* file, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RecordTimeSpanToFileAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::TimeSpan duration, void* file, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedScreenshotMediaEncodingSubtypes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveScreenshotToFilesAsync(void* folder, void* filenamePrefix, Windows::Media::AppRecording::AppRecordingSaveScreenshotOption option, void* requestedFormats, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::AppRecording::IAppRecordingManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::AppRecording::IAppRecordingResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsFileTruncated(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SavedScreenshotInfos(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_File(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaEncodingSubtype(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::AppRecording::IAppRecordingStatus>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanRecord(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanRecordTimeSpan(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HistoricalBufferDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Details(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::AppRecording::IAppRecordingStatusDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsAnyAppBroadcasting(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCaptureResourceUnavailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsGameStreamInProgress(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTimeSpanRecordingDisabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsGpuConstrained(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAppInactive(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBlockedForApp(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisabledByUser(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDisabledBySystem(bool* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingManager
{
    Windows::Media::AppRecording::AppRecordingStatus GetStatus() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult> StartRecordingToFileAsync(Windows::Storage::StorageFile const& file) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult> RecordTimeSpanToFileAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration, Windows::Storage::StorageFile const& file) const;
    Windows::Foundation::Collections::IVectorView<hstring> SupportedScreenshotMediaEncodingSubtypes() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult> SaveScreenshotToFilesAsync(Windows::Storage::StorageFolder const& folder, param::hstring const& filenamePrefix, Windows::Media::AppRecording::AppRecordingSaveScreenshotOption const& option, param::async_iterable<hstring> const& requestedFormats) const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingManager> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingManager<D>; };

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingManagerStatics
{
    Windows::Media::AppRecording::AppRecordingManager GetDefault() const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingManagerStatics> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingManagerStatics<D>; };

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingResult
{
    bool Succeeded() const;
    winrt::hresult ExtendedError() const;
    Windows::Foundation::TimeSpan Duration() const;
    bool IsFileTruncated() const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingResult> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingResult<D>; };

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingSaveScreenshotResult
{
    bool Succeeded() const;
    winrt::hresult ExtendedError() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo> SavedScreenshotInfos() const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingSaveScreenshotResult<D>; };

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingSavedScreenshotInfo
{
    Windows::Storage::StorageFile File() const;
    hstring MediaEncodingSubtype() const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingSavedScreenshotInfo<D>; };

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingStatus
{
    bool CanRecord() const;
    bool CanRecordTimeSpan() const;
    Windows::Foundation::TimeSpan HistoricalBufferDuration() const;
    Windows::Media::AppRecording::AppRecordingStatusDetails Details() const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingStatus> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingStatus<D>; };

template <typename D>
struct consume_Windows_Media_AppRecording_IAppRecordingStatusDetails
{
    bool IsAnyAppBroadcasting() const;
    bool IsCaptureResourceUnavailable() const;
    bool IsGameStreamInProgress() const;
    bool IsTimeSpanRecordingDisabled() const;
    bool IsGpuConstrained() const;
    bool IsAppInactive() const;
    bool IsBlockedForApp() const;
    bool IsDisabledByUser() const;
    bool IsDisabledBySystem() const;
};
template <> struct consume<Windows::Media::AppRecording::IAppRecordingStatusDetails> { template <typename D> using type = consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>; };

}
