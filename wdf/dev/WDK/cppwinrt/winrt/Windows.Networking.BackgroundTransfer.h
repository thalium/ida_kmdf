// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Networking.BackgroundTransfer.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> Windows::Networking::BackgroundTransfer::DownloadOperation consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader<D>::CreateDownload(Windows::Foundation::Uri const& uri, Windows::Storage::IStorageFile const& resultFile) const
{
    Windows::Networking::BackgroundTransfer::DownloadOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader)->CreateDownload(get_abi(uri), get_abi(resultFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::BackgroundTransfer::DownloadOperation consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader<D>::CreateDownload(Windows::Foundation::Uri const& uri, Windows::Storage::IStorageFile const& resultFile, Windows::Storage::IStorageFile const& requestBodyFile) const
{
    Windows::Networking::BackgroundTransfer::DownloadOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader)->CreateDownloadFromFile(get_abi(uri), get_abi(resultFile), get_abi(requestBodyFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::DownloadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader<D>::CreateDownloadAsync(Windows::Foundation::Uri const& uri, Windows::Storage::IStorageFile const& resultFile, Windows::Storage::Streams::IInputStream const& requestBodyStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::DownloadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader)->CreateDownloadAsync(get_abi(uri), get_abi(resultFile), get_abi(requestBodyStream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferGroup consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::TransferGroup() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_TransferGroup(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::TransferGroup(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_TransferGroup(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessToastNotification() const
{
    Windows::UI::Notifications::ToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_SuccessToastNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessToastNotification(Windows::UI::Notifications::ToastNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_SuccessToastNotification(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureToastNotification() const
{
    Windows::UI::Notifications::ToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_FailureToastNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureToastNotification(Windows::UI::Notifications::ToastNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_FailureToastNotification(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::TileNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessTileNotification() const
{
    Windows::UI::Notifications::TileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_SuccessTileNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessTileNotification(Windows::UI::Notifications::TileNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_SuccessTileNotification(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::TileNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureTileNotification() const
{
    Windows::UI::Notifications::TileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_FailureTileNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureTileNotification(Windows::UI::Notifications::TileNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_FailureTileNotification(get_abi(value)));
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader3<D>::CompletionGroup() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloader3)->get_CompletionGroup(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundDownloader consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderFactory<D>::CreateWithCompletionGroup(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) const
{
    Windows::Networking::BackgroundTransfer::BackgroundDownloader backgroundDownloader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory)->CreateWithCompletionGroup(get_abi(completionGroup), put_abi(backgroundDownloader)));
    return backgroundDownloader;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderStaticMethods<D>::GetCurrentDownloadsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods)->GetCurrentDownloadsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderStaticMethods<D>::GetCurrentDownloadsAsync(param::hstring const& group) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods)->GetCurrentDownloadsForGroupAsync(get_abi(group), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderStaticMethods2<D>::GetCurrentDownloadsForTransferGroupAsync(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2)->GetCurrentDownloadsForTransferGroupAsync(get_abi(group), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderUserConsent<D>::RequestUnconstrainedDownloadsAsync(param::async_iterable<Windows::Networking::BackgroundTransfer::DownloadOperation> const& operations) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent)->RequestUnconstrainedDownloadsAsync(get_abi(operations), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::SetRequestHeader(param::hstring const& headerName, param::hstring const& headerValue) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->SetRequestHeader(get_abi(headerName), get_abi(headerValue)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ServerCredential() const
{
    Windows::Security::Credentials::PasswordCredential credential{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_ServerCredential(put_abi(credential)));
    return credential;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ServerCredential(Windows::Security::Credentials::PasswordCredential const& credential) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_ServerCredential(get_abi(credential)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ProxyCredential() const
{
    Windows::Security::Credentials::PasswordCredential credential{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_ProxyCredential(put_abi(credential)));
    return credential;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ProxyCredential(Windows::Security::Credentials::PasswordCredential const& credential) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_ProxyCredential(get_abi(credential)));
}

template <typename D> hstring consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Method() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_Method(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Method(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_Method(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Group() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_Group(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Group(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_Group(get_abi(value)));
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::CostPolicy() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_CostPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::CostPolicy(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_CostPolicy(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Background::IBackgroundTrigger consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroup<D>::Trigger() const
{
    Windows::ApplicationModel::Background::IBackgroundTrigger value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup)->get_Trigger(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroup<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroup<D>::Enable() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup)->Enable());
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroupTriggerDetails<D>::Downloads() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails)->get_Downloads(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroupTriggerDetails<D>::Uploads() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails)->get_Uploads(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPart<D>::SetHeader(param::hstring const& headerName, param::hstring const& headerValue) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart)->SetHeader(get_abi(headerName), get_abi(headerValue)));
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPart<D>::SetText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart)->SetText(get_abi(value)));
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPart<D>::SetFile(Windows::Storage::IStorageFile const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart)->SetFile(get_abi(value)));
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPartFactory<D>::CreateWithName(param::hstring const& name) const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory)->CreateWithName(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPartFactory<D>::CreateWithNameAndFileName(param::hstring const& name, param::hstring const& fileName) const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory)->CreateWithNameAndFileName(get_abi(name), get_abi(fileName), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::WebErrorStatus consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferErrorStaticMethods<D>::GetStatus(int32_t hresult) const
{
    Windows::Web::WebErrorStatus status{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods)->GetStatus(hresult, put_abi(status)));
    return status;
}

template <typename D> hstring consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroup<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroup<D>::TransferBehavior() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup)->get_TransferBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroup<D>::TransferBehavior(Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup)->put_TransferBehavior(get_abi(value)));
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferGroup consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroupStatics<D>::CreateGroup(param::hstring const& name) const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics)->CreateGroup(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::Guid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_Guid(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::RequestedUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_RequestedUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::Method() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_Method(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::Group() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_Group(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::CostPolicy() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_CostPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::CostPolicy(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->put_CostPolicy(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::GetResultStreamAt(uint64_t position) const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->GetResultStreamAt(position, put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::ResponseInformation consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::GetResponseInformation() const
{
    Windows::Networking::BackgroundTransfer::ResponseInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->GetResponseInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferPriority consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperationPriority<D>::Priority() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferPriority value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority)->get_Priority(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperationPriority<D>::Priority(Windows::Networking::BackgroundTransfer::BackgroundTransferPriority const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority)->put_Priority(get_abi(value)));
}

template <typename D> bool consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferRangesDownloadedEventArgs<D>::WasDownloadRestarted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs)->get_WasDownloadRestarted(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange> consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferRangesDownloadedEventArgs<D>::AddedRanges() const
{
    Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs)->get_AddedRanges(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferRangesDownloadedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::BackgroundTransfer::UploadOperation consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUpload(Windows::Foundation::Uri const& uri, Windows::Storage::IStorageFile const& sourceFile) const
{
    Windows::Networking::BackgroundTransfer::UploadOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUpload(get_abi(uri), get_abi(sourceFile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadFromStreamAsync(Windows::Foundation::Uri const& uri, Windows::Storage::Streams::IInputStream const& sourceStream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadFromStreamAsync(get_abi(uri), get_abi(sourceStream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadAsync(Windows::Foundation::Uri const& uri, param::async_iterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const& parts) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadWithFormDataAndAutoBoundaryAsync(get_abi(uri), get_abi(parts), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadAsync(Windows::Foundation::Uri const& uri, param::async_iterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const& parts, param::hstring const& subType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadWithSubTypeAsync(get_abi(uri), get_abi(parts), get_abi(subType), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadAsync(Windows::Foundation::Uri const& uri, param::async_iterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const& parts, param::hstring const& subType, param::hstring const& boundary) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadWithSubTypeAndBoundaryAsync(get_abi(uri), get_abi(parts), get_abi(subType), get_abi(boundary), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferGroup consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::TransferGroup() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_TransferGroup(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::TransferGroup(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_TransferGroup(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessToastNotification() const
{
    Windows::UI::Notifications::ToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_SuccessToastNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessToastNotification(Windows::UI::Notifications::ToastNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_SuccessToastNotification(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::ToastNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureToastNotification() const
{
    Windows::UI::Notifications::ToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_FailureToastNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureToastNotification(Windows::UI::Notifications::ToastNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_FailureToastNotification(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::TileNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessTileNotification() const
{
    Windows::UI::Notifications::TileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_SuccessTileNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessTileNotification(Windows::UI::Notifications::TileNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_SuccessTileNotification(get_abi(value)));
}

template <typename D> Windows::UI::Notifications::TileNotification consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureTileNotification() const
{
    Windows::UI::Notifications::TileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_FailureTileNotification(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureTileNotification(Windows::UI::Notifications::TileNotification const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_FailureTileNotification(get_abi(value)));
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader3<D>::CompletionGroup() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploader3)->get_CompletionGroup(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundUploader consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderFactory<D>::CreateWithCompletionGroup(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) const
{
    Windows::Networking::BackgroundTransfer::BackgroundUploader backgroundUploader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory)->CreateWithCompletionGroup(get_abi(completionGroup), put_abi(backgroundUploader)));
    return backgroundUploader;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderStaticMethods<D>::GetCurrentUploadsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods)->GetCurrentUploadsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderStaticMethods<D>::GetCurrentUploadsAsync(param::hstring const& group) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods)->GetCurrentUploadsForGroupAsync(get_abi(group), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderStaticMethods2<D>::GetCurrentUploadsForTransferGroupAsync(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2)->GetCurrentUploadsForTransferGroupAsync(get_abi(group), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderUserConsent<D>::RequestUnconstrainedUploadsAsync(param::async_iterable<Windows::Networking::BackgroundTransfer::UploadOperation> const& operations) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent)->RequestUnconstrainedUploadsAsync(get_abi(operations), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Foundation::Uri> consume_Windows_Networking_BackgroundTransfer_IContentPrefetcher<D>::ContentUris() const
{
    Windows::Foundation::Collections::IVector<Windows::Foundation::Uri> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IContentPrefetcher)->get_ContentUris(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IContentPrefetcher<D>::IndirectContentUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IContentPrefetcher)->put_IndirectContentUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_BackgroundTransfer_IContentPrefetcher<D>::IndirectContentUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IContentPrefetcher)->get_IndirectContentUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Networking_BackgroundTransfer_IContentPrefetcherTime<D>::LastSuccessfulPrefetchTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IContentPrefetcherTime)->get_LastSuccessfulPrefetchTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::IStorageFile consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::ResultFile() const
{
    Windows::Storage::IStorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation)->get_ResultFile(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::Progress() const
{
    Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation)->get_Progress(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation> consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation> consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::AttachAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation)->AttachAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation)->Pause());
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation)->Resume());
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferGroup consume_Windows_Networking_BackgroundTransfer_IDownloadOperation2<D>::TransferGroup() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation2)->get_TransferGroup(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::IsRandomAccessRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->get_IsRandomAccessRequired(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::IsRandomAccessRequired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->put_IsRandomAccessRequired(value));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::GetResultRandomAccessStreamReference() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference stream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->GetResultRandomAccessStreamReference(put_abi(stream)));
    return stream;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange> consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::GetDownloadedRanges() const
{
    Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->GetDownloadedRanges(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded(Windows::Foundation::TypedEventHandler<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->add_RangesDownloaded(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded_revoker consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, RangesDownloaded_revoker>(this, RangesDownloaded(eventHandler));
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->remove_RangesDownloaded(get_abi(eventCookie)));
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RequestedUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->put_RequestedUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::WebErrorStatus> consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RecoverableWebErrorStatuses() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::WebErrorStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->get_RecoverableWebErrorStatuses(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Web::WebErrorStatus> consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::CurrentWebErrorStatus() const
{
    Windows::Foundation::IReference<Windows::Web::WebErrorStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation3)->get_CurrentWebErrorStatus(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IDownloadOperation4<D>::MakeCurrentInTransferGroup() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IDownloadOperation4)->MakeCurrentInTransferGroup());
}

template <typename D> bool consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::IsResumable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IResponseInformation)->get_IsResumable(&value));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::ActualUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IResponseInformation)->get_ActualUri(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::StatusCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IResponseInformation)->get_StatusCode(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, hstring> consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::Headers() const
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IResponseInformation)->get_Headers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_BackgroundTransfer_IUnconstrainedTransferRequestResult<D>::IsUnconstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult)->get_IsUnconstrained(&value));
    return value;
}

template <typename D> Windows::Storage::IStorageFile consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::SourceFile() const
{
    Windows::Storage::IStorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUploadOperation)->get_SourceFile(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundUploadProgress consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::Progress() const
{
    Windows::Networking::BackgroundTransfer::BackgroundUploadProgress value{};
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUploadOperation)->get_Progress(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUploadOperation)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation> consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::AttachAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUploadOperation)->AttachAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::BackgroundTransfer::BackgroundTransferGroup consume_Windows_Networking_BackgroundTransfer_IUploadOperation2<D>::TransferGroup() const
{
    Windows::Networking::BackgroundTransfer::BackgroundTransferGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUploadOperation2)->get_TransferGroup(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_BackgroundTransfer_IUploadOperation3<D>::MakeCurrentInTransferGroup() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::BackgroundTransfer::IUploadOperation3)->MakeCurrentInTransferGroup());
}

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloader> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloader>
{
    int32_t WINRT_CALL CreateDownload(void* uri, void* resultFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDownload, WINRT_WRAP(Windows::Networking::BackgroundTransfer::DownloadOperation), Windows::Foundation::Uri const&, Windows::Storage::IStorageFile const&);
            *operation = detach_from<Windows::Networking::BackgroundTransfer::DownloadOperation>(this->shim().CreateDownload(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&resultFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDownloadFromFile(void* uri, void* resultFile, void* requestBodyFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDownload, WINRT_WRAP(Windows::Networking::BackgroundTransfer::DownloadOperation), Windows::Foundation::Uri const&, Windows::Storage::IStorageFile const&, Windows::Storage::IStorageFile const&);
            *operation = detach_from<Windows::Networking::BackgroundTransfer::DownloadOperation>(this->shim().CreateDownload(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&resultFile), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&requestBodyFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDownloadAsync(void* uri, void* resultFile, void* requestBodyStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDownloadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::DownloadOperation>), Windows::Foundation::Uri const, Windows::Storage::IStorageFile const, Windows::Storage::Streams::IInputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().CreateDownloadAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&resultFile), *reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&requestBodyStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloader2> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloader2>
{
    int32_t WINRT_CALL get_TransferGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransferGroup(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferGroup, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const&);
            this->shim().TransferGroup(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuccessToastNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessToastNotification, WINRT_WRAP(Windows::UI::Notifications::ToastNotification));
            *value = detach_from<Windows::UI::Notifications::ToastNotification>(this->shim().SuccessToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuccessToastNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessToastNotification, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotification const&);
            this->shim().SuccessToastNotification(*reinterpret_cast<Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FailureToastNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureToastNotification, WINRT_WRAP(Windows::UI::Notifications::ToastNotification));
            *value = detach_from<Windows::UI::Notifications::ToastNotification>(this->shim().FailureToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FailureToastNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureToastNotification, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotification const&);
            this->shim().FailureToastNotification(*reinterpret_cast<Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuccessTileNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessTileNotification, WINRT_WRAP(Windows::UI::Notifications::TileNotification));
            *value = detach_from<Windows::UI::Notifications::TileNotification>(this->shim().SuccessTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuccessTileNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessTileNotification, WINRT_WRAP(void), Windows::UI::Notifications::TileNotification const&);
            this->shim().SuccessTileNotification(*reinterpret_cast<Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FailureTileNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureTileNotification, WINRT_WRAP(Windows::UI::Notifications::TileNotification));
            *value = detach_from<Windows::UI::Notifications::TileNotification>(this->shim().FailureTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FailureTileNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureTileNotification, WINRT_WRAP(void), Windows::UI::Notifications::TileNotification const&);
            this->shim().FailureTileNotification(*reinterpret_cast<Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloader3> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloader3>
{
    int32_t WINRT_CALL get_CompletionGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletionGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup>(this->shim().CompletionGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory>
{
    int32_t WINRT_CALL CreateWithCompletionGroup(void* completionGroup, void** backgroundDownloader) noexcept final
    {
        try
        {
            *backgroundDownloader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithCompletionGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundDownloader), Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const&);
            *backgroundDownloader = detach_from<Windows::Networking::BackgroundTransfer::BackgroundDownloader>(this->shim().CreateWithCompletionGroup(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const*>(&completionGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods>
{
    int32_t WINRT_CALL GetCurrentDownloadsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentDownloadsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>>(this->shim().GetCurrentDownloadsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentDownloadsForGroupAsync(void* group, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentDownloadsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>>(this->shim().GetCurrentDownloadsAsync(*reinterpret_cast<hstring const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2>
{
    int32_t WINRT_CALL GetCurrentDownloadsForTransferGroupAsync(void* group, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentDownloadsForTransferGroupAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>), Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>>(this->shim().GetCurrentDownloadsForTransferGroupAsync(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent>
{
    int32_t WINRT_CALL RequestUnconstrainedDownloadsAsync(void* operations, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUnconstrainedDownloadsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>), Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::DownloadOperation> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>>(this->shim().RequestUnconstrainedDownloadsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::DownloadOperation> const*>(&operations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferBase> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferBase>
{
    int32_t WINRT_CALL SetRequestHeader(void* headerName, void* headerValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRequestHeader, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCredential(void** credential) noexcept final
    {
        try
        {
            *credential = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *credential = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().ServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServerCredential(void* credential) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().ServerCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProxyCredential(void** credential) noexcept final
    {
        try
        {
            *credential = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *credential = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().ProxyCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProxyCredential(void* credential) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().ProxyCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Method(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Method, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Method());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Method(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Method, WINRT_WRAP(void), hstring const&);
            this->shim().Method(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Group(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Group(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(void), hstring const&);
            this->shim().Group(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CostPolicy(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CostPolicy, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy>(this->shim().CostPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CostPolicy(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CostPolicy, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const&);
            this->shim().CostPolicy(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup>
{
    int32_t WINRT_CALL get_Trigger(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Trigger, WINRT_WRAP(Windows::ApplicationModel::Background::IBackgroundTrigger));
            *value = detach_from<Windows::ApplicationModel::Background::IBackgroundTrigger>(this->shim().Trigger());
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

    int32_t WINRT_CALL Enable() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enable, WINRT_WRAP(void));
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails>
{
    int32_t WINRT_CALL get_Downloads(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Downloads, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().Downloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uploads(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uploads, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().Uploads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart>
{
    int32_t WINRT_CALL SetHeader(void* headerName, void* headerValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHeader, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().SetHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetText, WINRT_WRAP(void), hstring const&);
            this->shim().SetText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFile(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFile, WINRT_WRAP(void), Windows::Storage::IStorageFile const&);
            this->shim().SetFile(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory>
{
    int32_t WINRT_CALL CreateWithName(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithName, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart), hstring const&);
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart>(this->shim().CreateWithName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithNameAndFileName(void* name, void* fileName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithNameAndFileName, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart), hstring const&, hstring const&);
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart>(this->shim().CreateWithNameAndFileName(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&fileName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods>
{
    int32_t WINRT_CALL GetStatus(int32_t hresult, Windows::Web::WebErrorStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatus, WINRT_WRAP(Windows::Web::WebErrorStatus), int32_t);
            *status = detach_from<Windows::Web::WebErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransferBehavior(Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferBehavior, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior>(this->shim().TransferBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransferBehavior(Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferBehavior, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior const&);
            this->shim().TransferBehavior(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics>
{
    int32_t WINRT_CALL CreateGroup(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup), hstring const&);
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().CreateGroup(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation>
{
    int32_t WINRT_CALL get_Guid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Guid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Guid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().RequestedUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Method(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Method, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Method());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Group(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CostPolicy(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CostPolicy, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy>(this->shim().CostPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CostPolicy(Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CostPolicy, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const&);
            this->shim().CostPolicy(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetResultStreamAt(uint64_t position, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetResultStreamAt, WINRT_WRAP(Windows::Storage::Streams::IInputStream), uint64_t);
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().GetResultStreamAt(position));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetResponseInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetResponseInformation, WINRT_WRAP(Windows::Networking::BackgroundTransfer::ResponseInformation));
            *value = detach_from<Windows::Networking::BackgroundTransfer::ResponseInformation>(this->shim().GetResponseInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority>
{
    int32_t WINRT_CALL get_Priority(Windows::Networking::BackgroundTransfer::BackgroundTransferPriority* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferPriority));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferPriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Priority(Windows::Networking::BackgroundTransfer::BackgroundTransferPriority value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::BackgroundTransferPriority const&);
            this->shim().Priority(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs>
{
    int32_t WINRT_CALL get_WasDownloadRestarted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasDownloadRestarted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasDownloadRestarted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AddedRanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddedRanges, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>>(this->shim().AddedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploader> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploader>
{
    int32_t WINRT_CALL CreateUpload(void* uri, void* sourceFile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUpload, WINRT_WRAP(Windows::Networking::BackgroundTransfer::UploadOperation), Windows::Foundation::Uri const&, Windows::Storage::IStorageFile const&);
            *operation = detach_from<Windows::Networking::BackgroundTransfer::UploadOperation>(this->shim().CreateUpload(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&sourceFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUploadFromStreamAsync(void* uri, void* sourceStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUploadFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>), Windows::Foundation::Uri const, Windows::Storage::Streams::IInputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadFromStreamAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&sourceStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUploadWithFormDataAndAutoBoundaryAsync(void* uri, void* parts, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUploadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const*>(&parts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUploadWithSubTypeAsync(void* uri, void* parts, void* subType, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUploadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const*>(&parts), *reinterpret_cast<hstring const*>(&subType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUploadWithSubTypeAndBoundaryAsync(void* uri, void* parts, void* subType, void* boundary, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUploadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>), Windows::Foundation::Uri const, Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const*>(&parts), *reinterpret_cast<hstring const*>(&subType), *reinterpret_cast<hstring const*>(&boundary)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploader2> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploader2>
{
    int32_t WINRT_CALL get_TransferGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransferGroup(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferGroup, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const&);
            this->shim().TransferGroup(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuccessToastNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessToastNotification, WINRT_WRAP(Windows::UI::Notifications::ToastNotification));
            *value = detach_from<Windows::UI::Notifications::ToastNotification>(this->shim().SuccessToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuccessToastNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessToastNotification, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotification const&);
            this->shim().SuccessToastNotification(*reinterpret_cast<Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FailureToastNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureToastNotification, WINRT_WRAP(Windows::UI::Notifications::ToastNotification));
            *value = detach_from<Windows::UI::Notifications::ToastNotification>(this->shim().FailureToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FailureToastNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureToastNotification, WINRT_WRAP(void), Windows::UI::Notifications::ToastNotification const&);
            this->shim().FailureToastNotification(*reinterpret_cast<Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuccessTileNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessTileNotification, WINRT_WRAP(Windows::UI::Notifications::TileNotification));
            *value = detach_from<Windows::UI::Notifications::TileNotification>(this->shim().SuccessTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuccessTileNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuccessTileNotification, WINRT_WRAP(void), Windows::UI::Notifications::TileNotification const&);
            this->shim().SuccessTileNotification(*reinterpret_cast<Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FailureTileNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureTileNotification, WINRT_WRAP(Windows::UI::Notifications::TileNotification));
            *value = detach_from<Windows::UI::Notifications::TileNotification>(this->shim().FailureTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FailureTileNotification(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailureTileNotification, WINRT_WRAP(void), Windows::UI::Notifications::TileNotification const&);
            this->shim().FailureTileNotification(*reinterpret_cast<Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploader3> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploader3>
{
    int32_t WINRT_CALL get_CompletionGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletionGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup>(this->shim().CompletionGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory>
{
    int32_t WINRT_CALL CreateWithCompletionGroup(void* completionGroup, void** backgroundUploader) noexcept final
    {
        try
        {
            *backgroundUploader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithCompletionGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundUploader), Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const&);
            *backgroundUploader = detach_from<Windows::Networking::BackgroundTransfer::BackgroundUploader>(this->shim().CreateWithCompletionGroup(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const*>(&completionGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods>
{
    int32_t WINRT_CALL GetCurrentUploadsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentUploadsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>>(this->shim().GetCurrentUploadsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentUploadsForGroupAsync(void* group, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentUploadsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>>(this->shim().GetCurrentUploadsAsync(*reinterpret_cast<hstring const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2>
{
    int32_t WINRT_CALL GetCurrentUploadsForTransferGroupAsync(void* group, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentUploadsForTransferGroupAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>), Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>>>(this->shim().GetCurrentUploadsForTransferGroupAsync(*reinterpret_cast<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent> : produce_base<D, Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent>
{
    int32_t WINRT_CALL RequestUnconstrainedUploadsAsync(void* operations, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUnconstrainedUploadsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>), Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::UploadOperation> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>>(this->shim().RequestUnconstrainedUploadsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::BackgroundTransfer::UploadOperation> const*>(&operations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IContentPrefetcher> : produce_base<D, Windows::Networking::BackgroundTransfer::IContentPrefetcher>
{
    int32_t WINRT_CALL get_ContentUris(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentUris, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Foundation::Uri>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Foundation::Uri>>(this->shim().ContentUris());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IndirectContentUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndirectContentUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().IndirectContentUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndirectContentUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndirectContentUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().IndirectContentUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IContentPrefetcherTime> : produce_base<D, Windows::Networking::BackgroundTransfer::IContentPrefetcherTime>
{
    int32_t WINRT_CALL get_LastSuccessfulPrefetchTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSuccessfulPrefetchTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().LastSuccessfulPrefetchTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IDownloadOperation> : produce_base<D, Windows::Networking::BackgroundTransfer::IDownloadOperation>
{
    int32_t WINRT_CALL get_ResultFile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResultFile, WINRT_WRAP(Windows::Storage::IStorageFile));
            *value = detach_from<Windows::Storage::IStorageFile>(this->shim().ResultFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(struct struct_Windows_Networking_BackgroundTransfer_BackgroundDownloadProgress* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AttachAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().AttachAsync());
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
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IDownloadOperation2> : produce_base<D, Windows::Networking::BackgroundTransfer::IDownloadOperation2>
{
    int32_t WINRT_CALL get_TransferGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IDownloadOperation3> : produce_base<D, Windows::Networking::BackgroundTransfer::IDownloadOperation3>
{
    int32_t WINRT_CALL get_IsRandomAccessRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRandomAccessRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRandomAccessRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRandomAccessRequired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRandomAccessRequired, WINRT_WRAP(void), bool);
            this->shim().IsRandomAccessRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetResultRandomAccessStreamReference(void** stream) noexcept final
    {
        try
        {
            *stream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetResultRandomAccessStreamReference, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *stream = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().GetResultRandomAccessStreamReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDownloadedRanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDownloadedRanges, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>>(this->shim().GetDownloadedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RangesDownloaded(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RangesDownloaded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().RangesDownloaded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::BackgroundTransfer::DownloadOperation, Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RangesDownloaded(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RangesDownloaded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RangesDownloaded(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL put_RequestedUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().RequestedUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecoverableWebErrorStatuses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecoverableWebErrorStatuses, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::WebErrorStatus>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::WebErrorStatus>>(this->shim().RecoverableWebErrorStatuses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentWebErrorStatus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentWebErrorStatus, WINRT_WRAP(Windows::Foundation::IReference<Windows::Web::WebErrorStatus>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Web::WebErrorStatus>>(this->shim().CurrentWebErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IDownloadOperation4> : produce_base<D, Windows::Networking::BackgroundTransfer::IDownloadOperation4>
{
    int32_t WINRT_CALL MakeCurrentInTransferGroup() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MakeCurrentInTransferGroup, WINRT_WRAP(void));
            this->shim().MakeCurrentInTransferGroup();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IResponseInformation> : produce_base<D, Windows::Networking::BackgroundTransfer::IResponseInformation>
{
    int32_t WINRT_CALL get_IsResumable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResumable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsResumable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ActualUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StatusCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().StatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Headers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headers, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult> : produce_base<D, Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult>
{
    int32_t WINRT_CALL get_IsUnconstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUnconstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUnconstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IUploadOperation> : produce_base<D, Windows::Networking::BackgroundTransfer::IUploadOperation>
{
    int32_t WINRT_CALL get_SourceFile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceFile, WINRT_WRAP(Windows::Storage::IStorageFile));
            *value = detach_from<Windows::Storage::IStorageFile>(this->shim().SourceFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(struct struct_Windows_Networking_BackgroundTransfer_BackgroundUploadProgress* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundUploadProgress));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundUploadProgress>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AttachAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttachAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::BackgroundTransfer::UploadOperation, Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().AttachAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IUploadOperation2> : produce_base<D, Windows::Networking::BackgroundTransfer::IUploadOperation2>
{
    int32_t WINRT_CALL get_TransferGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferGroup, WINRT_WRAP(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup));
            *value = detach_from<Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::BackgroundTransfer::IUploadOperation3> : produce_base<D, Windows::Networking::BackgroundTransfer::IUploadOperation3>
{
    int32_t WINRT_CALL MakeCurrentInTransferGroup() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MakeCurrentInTransferGroup, WINRT_WRAP(void));
            this->shim().MakeCurrentInTransferGroup();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Networking::BackgroundTransfer {

inline BackgroundDownloader::BackgroundDownloader() :
    BackgroundDownloader(impl::call_factory<BackgroundDownloader>([](auto&& f) { return f.template ActivateInstance<BackgroundDownloader>(); }))
{}

inline BackgroundDownloader::BackgroundDownloader(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) :
    BackgroundDownloader(impl::call_factory<BackgroundDownloader, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory>([&](auto&& f) { return f.CreateWithCompletionGroup(completionGroup); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> BackgroundDownloader::GetCurrentDownloadsAsync()
{
    return impl::call_factory<BackgroundDownloader, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods>([&](auto&& f) { return f.GetCurrentDownloadsAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> BackgroundDownloader::GetCurrentDownloadsAsync(param::hstring const& group)
{
    return impl::call_factory<BackgroundDownloader, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods>([&](auto&& f) { return f.GetCurrentDownloadsAsync(group); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::DownloadOperation>> BackgroundDownloader::GetCurrentDownloadsForTransferGroupAsync(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group)
{
    return impl::call_factory<BackgroundDownloader, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2>([&](auto&& f) { return f.GetCurrentDownloadsForTransferGroupAsync(group); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> BackgroundDownloader::RequestUnconstrainedDownloadsAsync(param::async_iterable<Windows::Networking::BackgroundTransfer::DownloadOperation> const& operations)
{
    return impl::call_factory<BackgroundDownloader, Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent>([&](auto&& f) { return f.RequestUnconstrainedDownloadsAsync(operations); });
}

inline BackgroundTransferCompletionGroup::BackgroundTransferCompletionGroup() :
    BackgroundTransferCompletionGroup(impl::call_factory<BackgroundTransferCompletionGroup>([](auto&& f) { return f.template ActivateInstance<BackgroundTransferCompletionGroup>(); }))
{}

inline BackgroundTransferContentPart::BackgroundTransferContentPart() :
    BackgroundTransferContentPart(impl::call_factory<BackgroundTransferContentPart>([](auto&& f) { return f.template ActivateInstance<BackgroundTransferContentPart>(); }))
{}

inline BackgroundTransferContentPart::BackgroundTransferContentPart(param::hstring const& name) :
    BackgroundTransferContentPart(impl::call_factory<BackgroundTransferContentPart, Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory>([&](auto&& f) { return f.CreateWithName(name); }))
{}

inline BackgroundTransferContentPart::BackgroundTransferContentPart(param::hstring const& name, param::hstring const& fileName) :
    BackgroundTransferContentPart(impl::call_factory<BackgroundTransferContentPart, Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory>([&](auto&& f) { return f.CreateWithNameAndFileName(name, fileName); }))
{}

inline Windows::Web::WebErrorStatus BackgroundTransferError::GetStatus(int32_t hresult)
{
    return impl::call_factory<BackgroundTransferError, Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods>([&](auto&& f) { return f.GetStatus(hresult); });
}

inline Windows::Networking::BackgroundTransfer::BackgroundTransferGroup BackgroundTransferGroup::CreateGroup(param::hstring const& name)
{
    return impl::call_factory<BackgroundTransferGroup, Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics>([&](auto&& f) { return f.CreateGroup(name); });
}

inline BackgroundUploader::BackgroundUploader() :
    BackgroundUploader(impl::call_factory<BackgroundUploader>([](auto&& f) { return f.template ActivateInstance<BackgroundUploader>(); }))
{}

inline BackgroundUploader::BackgroundUploader(Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) :
    BackgroundUploader(impl::call_factory<BackgroundUploader, Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory>([&](auto&& f) { return f.CreateWithCompletionGroup(completionGroup); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> BackgroundUploader::GetCurrentUploadsAsync()
{
    return impl::call_factory<BackgroundUploader, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods>([&](auto&& f) { return f.GetCurrentUploadsAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> BackgroundUploader::GetCurrentUploadsAsync(param::hstring const& group)
{
    return impl::call_factory<BackgroundUploader, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods>([&](auto&& f) { return f.GetCurrentUploadsAsync(group); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::BackgroundTransfer::UploadOperation>> BackgroundUploader::GetCurrentUploadsForTransferGroupAsync(Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group)
{
    return impl::call_factory<BackgroundUploader, Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2>([&](auto&& f) { return f.GetCurrentUploadsForTransferGroupAsync(group); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> BackgroundUploader::RequestUnconstrainedUploadsAsync(param::async_iterable<Windows::Networking::BackgroundTransfer::UploadOperation> const& operations)
{
    return impl::call_factory<BackgroundUploader, Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent>([&](auto&& f) { return f.RequestUnconstrainedUploadsAsync(operations); });
}

inline Windows::Foundation::Collections::IVector<Windows::Foundation::Uri> ContentPrefetcher::ContentUris()
{
    return impl::call_factory<ContentPrefetcher, Windows::Networking::BackgroundTransfer::IContentPrefetcher>([&](auto&& f) { return f.ContentUris(); });
}

inline void ContentPrefetcher::IndirectContentUri(Windows::Foundation::Uri const& value)
{
    impl::call_factory<ContentPrefetcher, Windows::Networking::BackgroundTransfer::IContentPrefetcher>([&](auto&& f) { return f.IndirectContentUri(value); });
}

inline Windows::Foundation::Uri ContentPrefetcher::IndirectContentUri()
{
    return impl::call_factory<ContentPrefetcher, Windows::Networking::BackgroundTransfer::IContentPrefetcher>([&](auto&& f) { return f.IndirectContentUri(); });
}

inline Windows::Foundation::IReference<Windows::Foundation::DateTime> ContentPrefetcher::LastSuccessfulPrefetchTime()
{
    return impl::call_factory<ContentPrefetcher, Windows::Networking::BackgroundTransfer::IContentPrefetcherTime>([&](auto&& f) { return f.LastSuccessfulPrefetchTime(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader3> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader3> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader3> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader3> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcherTime> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcherTime> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation2> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation2> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation4> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation4> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IResponseInformation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IResponseInformation> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation2> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation2> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation3> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation3> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloader> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloader> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroupTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroupTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferError> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferError> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundUploader> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::BackgroundUploader> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::ContentPrefetcher> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::ContentPrefetcher> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::ResponseInformation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::ResponseInformation> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> {};
template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::UploadOperation> : winrt::impl::hash_base<winrt::Windows::Networking::BackgroundTransfer::UploadOperation> {};

}
