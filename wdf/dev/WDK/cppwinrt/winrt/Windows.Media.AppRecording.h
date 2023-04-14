// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Media.AppRecording.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::AppRecording::AppRecordingStatus consume_Windows_Media_AppRecording_IAppRecordingManager<D>::GetStatus() const
{
    Windows::Media::AppRecording::AppRecordingStatus result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingManager)->GetStatus(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult> consume_Windows_Media_AppRecording_IAppRecordingManager<D>::StartRecordingToFileAsync(Windows::Storage::StorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingManager)->StartRecordingToFileAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult> consume_Windows_Media_AppRecording_IAppRecordingManager<D>::RecordTimeSpanToFileAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration, Windows::Storage::StorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingManager)->RecordTimeSpanToFileAsync(get_abi(startTime), get_abi(duration), get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Media_AppRecording_IAppRecordingManager<D>::SupportedScreenshotMediaEncodingSubtypes() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingManager)->get_SupportedScreenshotMediaEncodingSubtypes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult> consume_Windows_Media_AppRecording_IAppRecordingManager<D>::SaveScreenshotToFilesAsync(Windows::Storage::StorageFolder const& folder, param::hstring const& filenamePrefix, Windows::Media::AppRecording::AppRecordingSaveScreenshotOption const& option, param::async_iterable<hstring> const& requestedFormats) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingManager)->SaveScreenshotToFilesAsync(get_abi(folder), get_abi(filenamePrefix), get_abi(option), get_abi(requestedFormats), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::AppRecording::AppRecordingManager consume_Windows_Media_AppRecording_IAppRecordingManagerStatics<D>::GetDefault() const
{
    Windows::Media::AppRecording::AppRecordingManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingManagerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingResult)->get_Succeeded(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_AppRecording_IAppRecordingResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_AppRecording_IAppRecordingResult<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingResult)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingResult<D>::IsFileTruncated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingResult)->get_IsFileTruncated(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingSaveScreenshotResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult)->get_Succeeded(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_AppRecording_IAppRecordingSaveScreenshotResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo> consume_Windows_Media_AppRecording_IAppRecordingSaveScreenshotResult<D>::SavedScreenshotInfos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult)->get_SavedScreenshotInfos(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Media_AppRecording_IAppRecordingSavedScreenshotInfo<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo)->get_File(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_AppRecording_IAppRecordingSavedScreenshotInfo<D>::MediaEncodingSubtype() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo)->get_MediaEncodingSubtype(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatus<D>::CanRecord() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatus)->get_CanRecord(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatus<D>::CanRecordTimeSpan() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatus)->get_CanRecordTimeSpan(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_AppRecording_IAppRecordingStatus<D>::HistoricalBufferDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatus)->get_HistoricalBufferDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::AppRecording::AppRecordingStatusDetails consume_Windows_Media_AppRecording_IAppRecordingStatus<D>::Details() const
{
    Windows::Media::AppRecording::AppRecordingStatusDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatus)->get_Details(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsAnyAppBroadcasting() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsAnyAppBroadcasting(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsCaptureResourceUnavailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsCaptureResourceUnavailable(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsGameStreamInProgress() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsGameStreamInProgress(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsTimeSpanRecordingDisabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsTimeSpanRecordingDisabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsGpuConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsGpuConstrained(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsAppInactive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsAppInactive(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsBlockedForApp() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsBlockedForApp(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsDisabledByUser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsDisabledByUser(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppRecording_IAppRecordingStatusDetails<D>::IsDisabledBySystem() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppRecording::IAppRecordingStatusDetails)->get_IsDisabledBySystem(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingManager> : produce_base<D, Windows::Media::AppRecording::IAppRecordingManager>
{
    int32_t WINRT_CALL GetStatus(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatus, WINRT_WRAP(Windows::Media::AppRecording::AppRecordingStatus));
            *result = detach_from<Windows::Media::AppRecording::AppRecordingStatus>(this->shim().GetStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartRecordingToFileAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartRecordingToFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult>), Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult>>(this->shim().StartRecordingToFileAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecordTimeSpanToFileAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::TimeSpan duration, void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordTimeSpanToFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult>), Windows::Foundation::DateTime const, Windows::Foundation::TimeSpan const, Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingResult>>(this->shim().RecordTimeSpanToFileAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration), *reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedScreenshotMediaEncodingSubtypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedScreenshotMediaEncodingSubtypes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedScreenshotMediaEncodingSubtypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveScreenshotToFilesAsync(void* folder, void* filenamePrefix, Windows::Media::AppRecording::AppRecordingSaveScreenshotOption option, void* requestedFormats, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveScreenshotToFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult>), Windows::Storage::StorageFolder const, hstring const, Windows::Media::AppRecording::AppRecordingSaveScreenshotOption const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::AppRecording::AppRecordingSaveScreenshotResult>>(this->shim().SaveScreenshotToFilesAsync(*reinterpret_cast<Windows::Storage::StorageFolder const*>(&folder), *reinterpret_cast<hstring const*>(&filenamePrefix), *reinterpret_cast<Windows::Media::AppRecording::AppRecordingSaveScreenshotOption const*>(&option), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requestedFormats)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingManagerStatics> : produce_base<D, Windows::Media::AppRecording::IAppRecordingManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Media::AppRecording::AppRecordingManager));
            *result = detach_from<Windows::Media::AppRecording::AppRecordingManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingResult> : produce_base<D, Windows::Media::AppRecording::IAppRecordingResult>
{
    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
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

    int32_t WINRT_CALL get_IsFileTruncated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFileTruncated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFileTruncated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult> : produce_base<D, Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult>
{
    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
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

    int32_t WINRT_CALL get_SavedScreenshotInfos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SavedScreenshotInfos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo>>(this->shim().SavedScreenshotInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo> : produce_base<D, Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo>
{
    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaEncodingSubtype(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaEncodingSubtype, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MediaEncodingSubtype());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingStatus> : produce_base<D, Windows::Media::AppRecording::IAppRecordingStatus>
{
    int32_t WINRT_CALL get_CanRecord(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRecord, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanRecord());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanRecordTimeSpan(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRecordTimeSpan, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanRecordTimeSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HistoricalBufferDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalBufferDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().HistoricalBufferDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Details(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Details, WINRT_WRAP(Windows::Media::AppRecording::AppRecordingStatusDetails));
            *value = detach_from<Windows::Media::AppRecording::AppRecordingStatusDetails>(this->shim().Details());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppRecording::IAppRecordingStatusDetails> : produce_base<D, Windows::Media::AppRecording::IAppRecordingStatusDetails>
{
    int32_t WINRT_CALL get_IsAnyAppBroadcasting(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAnyAppBroadcasting, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAnyAppBroadcasting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCaptureResourceUnavailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCaptureResourceUnavailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCaptureResourceUnavailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGameStreamInProgress(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGameStreamInProgress, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGameStreamInProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTimeSpanRecordingDisabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTimeSpanRecordingDisabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTimeSpanRecordingDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGpuConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGpuConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAppInactive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppInactive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppInactive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBlockedForApp(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlockedForApp, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBlockedForApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledByUser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledByUser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledBySystem(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledBySystem, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::AppRecording {

inline Windows::Media::AppRecording::AppRecordingManager AppRecordingManager::GetDefault()
{
    return impl::call_factory<AppRecordingManager, Windows::Media::AppRecording::IAppRecordingManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingManager> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingManager> {};
template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingManagerStatics> {};
template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingResult> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingResult> {};
template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult> {};
template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo> {};
template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingStatus> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingStatus> {};
template<> struct hash<winrt::Windows::Media::AppRecording::IAppRecordingStatusDetails> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::IAppRecordingStatusDetails> {};
template<> struct hash<winrt::Windows::Media::AppRecording::AppRecordingManager> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::AppRecordingManager> {};
template<> struct hash<winrt::Windows::Media::AppRecording::AppRecordingResult> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::AppRecordingResult> {};
template<> struct hash<winrt::Windows::Media::AppRecording::AppRecordingSaveScreenshotResult> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::AppRecordingSaveScreenshotResult> {};
template<> struct hash<winrt::Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::AppRecordingSavedScreenshotInfo> {};
template<> struct hash<winrt::Windows::Media::AppRecording::AppRecordingStatus> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::AppRecordingStatus> {};
template<> struct hash<winrt::Windows::Media::AppRecording::AppRecordingStatusDetails> : winrt::impl::hash_base<winrt::Windows::Media::AppRecording::AppRecordingStatusDetails> {};

}
