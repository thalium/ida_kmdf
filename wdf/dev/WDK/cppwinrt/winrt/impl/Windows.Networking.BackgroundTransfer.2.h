// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Background.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Security.Credentials.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.UI.Notifications.1.h"
#include "winrt/impl/Windows.Web.1.h"
#include "winrt/impl/Windows.Networking.BackgroundTransfer.1.h"

WINRT_EXPORT namespace winrt::Windows::Networking::BackgroundTransfer {

struct BackgroundDownloadProgress
{
    uint64_t BytesReceived;
    uint64_t TotalBytesToReceive;
    Windows::Networking::BackgroundTransfer::BackgroundTransferStatus Status;
    bool HasResponseChanged;
    bool HasRestarted;
};

inline bool operator==(BackgroundDownloadProgress const& left, BackgroundDownloadProgress const& right) noexcept
{
    return left.BytesReceived == right.BytesReceived && left.TotalBytesToReceive == right.TotalBytesToReceive && left.Status == right.Status && left.HasResponseChanged == right.HasResponseChanged && left.HasRestarted == right.HasRestarted;
}

inline bool operator!=(BackgroundDownloadProgress const& left, BackgroundDownloadProgress const& right) noexcept
{
    return !(left == right);
}

struct BackgroundTransferFileRange
{
    uint64_t Offset;
    uint64_t Length;
};

inline bool operator==(BackgroundTransferFileRange const& left, BackgroundTransferFileRange const& right) noexcept
{
    return left.Offset == right.Offset && left.Length == right.Length;
}

inline bool operator!=(BackgroundTransferFileRange const& left, BackgroundTransferFileRange const& right) noexcept
{
    return !(left == right);
}

struct BackgroundUploadProgress
{
    uint64_t BytesReceived;
    uint64_t BytesSent;
    uint64_t TotalBytesToReceive;
    uint64_t TotalBytesToSend;
    Windows::Networking::BackgroundTransfer::BackgroundTransferStatus Status;
    bool HasResponseChanged;
    bool HasRestarted;
};

inline bool operator==(BackgroundUploadProgress const& left, BackgroundUploadProgress const& right) noexcept
{
    return left.BytesReceived == right.BytesReceived && left.BytesSent == right.BytesSent && left.TotalBytesToReceive == right.TotalBytesToReceive && left.TotalBytesToSend == right.TotalBytesToSend && left.Status == right.Status && left.HasResponseChanged == right.HasResponseChanged && left.HasRestarted == right.HasRestarted;
}

inline bool operator!=(BackgroundUploadProgress const& left, BackgroundUploadProgress const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Networking::BackgroundTransfer {

struct WINRT_EBO BackgroundDownloader :
    Windows::Networking::BackgroundTransfer::IBackgroundDownloader,
    impl::require<BackgroundDownloader, Windows::Networking::BackgroundTransfer::IBackgroundDownloader2, Windows::Networking::BackgroundTransfer::IBackgroundDownloader3>
{
    BackgroundDownloader(std::nullptr_t) noexcept {}
    BackgroundDownloader();
    BackgroundDownloader(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> GetCurrentDownloadsAsync();
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> GetCurrentDownloadsAsync(param::hstring const& group);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> GetCurrentDownloadsForTransferGroupAsync(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group);
    static Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> RequestUnconstrainedDownloadsAsync(param::async_iterable<Windows::Networking::BackgroundTransfer::DownloadOperation> const& operations);
};

struct WINRT_EBO BackgroundTransferCompletionGroup :
    Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup
{
    BackgroundTransferCompletionGroup(std::nullptr_t) noexcept {}
    BackgroundTransferCompletionGroup();
};

struct WINRT_EBO BackgroundTransferCompletionGroupTriggerDetails :
    Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails
{
    BackgroundTransferCompletionGroupTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BackgroundTransferContentPart :
    Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart
{
    BackgroundTransferContentPart(std::nullptr_t) noexcept {}
    BackgroundTransferContentPart();
    BackgroundTransferContentPart(param::hstring const& name);
    BackgroundTransferContentPart(param::hstring const& name, param::hstring const& fileName);
};

struct BackgroundTransferError
{
    BackgroundTransferError() = delete;
    static Windows::Web::WebErrorStatus GetStatus(int32_t hresult);
};

struct WINRT_EBO BackgroundTransferGroup :
    Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup
{
    BackgroundTransferGroup(std::nullptr_t) noexcept {}
    static Windows::Networking::BackgroundTransfer::BackgroundTransferGroup CreateGroup(param::hstring const& name);
};

struct WINRT_EBO BackgroundTransferRangesDownloadedEventArgs :
    Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs
{
    BackgroundTransferRangesDownloadedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BackgroundUploader :
    Windows::Networking::BackgroundTransfer::IBackgroundUploader,
    impl::require<BackgroundUploader, Windows::Networking::BackgroundTransfer::IBackgroundUploader2, Windows::Networking::BackgroundTransfer::IBackgroundUploader3>
{
    BackgroundUploader(std::nullptr_t) noexcept {}
    BackgroundUploader();
    BackgroundUploader(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> GetCurrentUploadsAsync();
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> GetCurrentUploadsAsync(param::hstring const& group);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> GetCurrentUploadsForTransferGroupAsync(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group);
    static Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> RequestUnconstrainedUploadsAsync(param::async_iterable<Windows::Networking::BackgroundTransfer::UploadOperation> const& operations);
};

struct ContentPrefetcher
{
    ContentPrefetcher() = delete;
    static Windows::Foundation::Collections::IVector<Windows::Foundation::Uri> ContentUris();
    static void IndirectContentUri(Windows::Foundation::Uri const& value);
    static Windows::Foundation::Uri IndirectContentUri();
    static Windows::Foundation::IReference<Windows::Foundation::DateTime> LastSuccessfulPrefetchTime();
};

struct WINRT_EBO DownloadOperation :
    Windows::Networking::BackgroundTransfer::IDownloadOperation,
    impl::require<DownloadOperation, Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority, Windows::Networking::BackgroundTransfer::IDownloadOperation2, Windows::Networking::BackgroundTransfer::IDownloadOperation3, Windows::Networking::BackgroundTransfer::IDownloadOperation4>
{
    DownloadOperation(std::nullptr_t) noexcept {}
    using impl::consume_t<DownloadOperation, Windows::Networking::BackgroundTransfer::IDownloadOperation3>::RequestedUri;
    using Windows::Networking::BackgroundTransfer::IDownloadOperation::RequestedUri;
};

struct WINRT_EBO ResponseInformation :
    Windows::Networking::BackgroundTransfer::IResponseInformation
{
    ResponseInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UnconstrainedTransferRequestResult :
    Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult
{
    UnconstrainedTransferRequestResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UploadOperation :
    Windows::Networking::BackgroundTransfer::IUploadOperation,
    impl::require<UploadOperation, Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority, Windows::Networking::BackgroundTransfer::IUploadOperation2, Windows::Networking::BackgroundTransfer::IUploadOperation3>
{
    UploadOperation(std::nullptr_t) noexcept {}
};

}
