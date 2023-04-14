// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Media.AppRecording.0.h"

WINRT_EXPORT namespace winrt::Windows::Media::AppRecording {

struct WINRT_EBO IAppRecordingManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingManager>
{
    IAppRecordingManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppRecordingManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingManagerStatics>
{
    IAppRecordingManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppRecordingResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingResult>
{
    IAppRecordingResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppRecordingSaveScreenshotResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingSaveScreenshotResult>
{
    IAppRecordingSaveScreenshotResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppRecordingSavedScreenshotInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingSavedScreenshotInfo>
{
    IAppRecordingSavedScreenshotInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppRecordingStatus :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingStatus>
{
    IAppRecordingStatus(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppRecordingStatusDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppRecordingStatusDetails>
{
    IAppRecordingStatusDetails(std::nullptr_t = nullptr) noexcept {}
};

}
