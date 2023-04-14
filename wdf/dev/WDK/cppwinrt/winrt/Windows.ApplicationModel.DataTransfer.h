// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.EnterpriseData.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsRoamable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_IsRoamable(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsRoamable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->put_IsRoamable(value));
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsAllowedInHistory() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_IsAllowedInHistory(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsAllowedInHistory(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->put_IsAllowedInHistory(value));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::RoamingFormats() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_RoamingFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::HistoryFormats() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_HistoryFormats(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>::Content() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItemsResult<D>::Status() const
{
    Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem> consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItemsResult<D>::Items() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult)->get_Items(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::GetContent() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics)->GetContent(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::SetContent(Windows::ApplicationModel::DataTransfer::DataPackage const& content) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics)->SetContent(get_abi(content)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::Flush() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics)->Flush());
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics)->Clear());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics)->add_ContentChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ContentChanged_revoker>(this, ContentChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics)->remove_ContentChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::GetHistoryItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->GetHistoryItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::ClearHistory() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->ClearHistory(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::DeleteItemFromHistory(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->DeleteItemFromHistory(get_abi(item), &result));
    return result;
}

template <typename D> Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::SetHistoryItemAsContent(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item) const
{
    Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->SetHistoryItemAsContent(get_abi(item), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::IsHistoryEnabled() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->IsHistoryEnabled(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::IsRoamingEnabled() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->IsRoamingEnabled(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::SetContentWithOptions(Windows::ApplicationModel::DataTransfer::DataPackage const& content, Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->SetContentWithOptions(get_abi(content), get_abi(options), &result));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged(Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->add_HistoryChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HistoryChanged_revoker>(this, HistoryChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->remove_HistoryChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->add_RoamingEnabledChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RoamingEnabledChanged_revoker>(this, RoamingEnabledChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->remove_RoamingEnabledChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->add_HistoryEnabledChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, HistoryEnabledChanged_revoker>(this, HistoryEnabledChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->remove_HistoryEnabledChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::GetView() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->GetView(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackagePropertySet consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Properties() const
{
    Windows::ApplicationModel::DataTransfer::DataPackagePropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::RequestedOperation() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->get_RequestedOperation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->put_RequestedOperation(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const& handler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->add_OperationCompleted(get_abi(handler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OperationCompleted_revoker>(this, OperationCompleted(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->remove_OperationCompleted(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->add_Destroyed(get_abi(handler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Destroyed_revoker>(this, Destroyed(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->remove_Destroyed(get_abi(eventCookie)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetData(param::hstring const& formatId, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetData(get_abi(formatId), get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetDataProvider(param::hstring const& formatId, Windows::ApplicationModel::DataTransfer::DataProviderHandler const& delayRenderer) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetDataProvider(get_abi(formatId), get_abi(delayRenderer)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetText(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetUri(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetHtmlFormat(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetHtmlFormat(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::Storage::Streams::RandomAccessStreamReference> consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::ResourceMap() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::Storage::Streams::RandomAccessStreamReference> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->get_ResourceMap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetRtf(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetRtf(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetBitmap(Windows::Storage::Streams::RandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetBitmap(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetStorageItems(param::iterable<Windows::Storage::IStorageItem> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetStorageItemsReadOnly(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetStorageItems(param::iterable<Windows::Storage::IStorageItem> const& value, bool readOnly) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage)->SetStorageItems(get_abi(value), readOnly));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage2<D>::SetApplicationLink(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage2)->SetApplicationLink(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage2<D>::SetWebLink(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage2)->SetWebLink(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage3)->add_ShareCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ShareCompleted_revoker>(this, ShareCompleted(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackage3)->remove_ShareCompleted(get_abi(token)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_Description(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::FileTypes() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_FileTypes(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_ApplicationName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_ApplicationName(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationListingUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_ApplicationListingUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationListingUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_ApplicationListingUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceWebLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_ContentSourceWebLink(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceWebLink(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_ContentSourceWebLink(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceApplicationLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_ContentSourceApplicationLink(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceApplicationLink(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_ContentSourceApplicationLink(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::PackageFamilyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_PackageFamilyName(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::Square30x30Logo() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_Square30x30Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::Square30x30Logo(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_Square30x30Logo(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::LogoBackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_LogoBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::LogoBackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_LogoBackgroundColor(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet3<D>::EnterpriseId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3)->get_EnterpriseId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet3<D>::EnterpriseId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3)->put_EnterpriseId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet4<D>::ContentSourceUserActivityJson() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4)->get_ContentSourceUserActivityJson(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet4<D>::ContentSourceUserActivityJson(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4)->put_ContentSourceUserActivityJson(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::Thumbnail() const
{
    Windows::Storage::Streams::RandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::FileTypes() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_FileTypes(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::ApplicationName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_ApplicationName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::ApplicationListingUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_ApplicationListingUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::ContentSourceWebLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_ContentSourceWebLink(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::ContentSourceApplicationLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_ContentSourceApplicationLink(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::Square30x30Logo() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_Square30x30Logo(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::LogoBackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_LogoBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView3<D>::EnterpriseId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3)->get_EnterpriseId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView4<D>::ContentSourceUserActivityJson() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4)->get_ContentSourceUserActivityJson(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView5<D>::IsFromRoamingClipboard() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5)->get_IsFromRoamingClipboard(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::Properties() const
{
    Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::RequestedOperation() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->get_RequestedOperation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::ReportOperationCompleted(Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->ReportOperationCompleted(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::AvailableFormats() const
{
    Windows::Foundation::Collections::IVectorView<hstring> formatIds{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->get_AvailableFormats(put_abi(formatIds)));
    return formatIds;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::Contains(param::hstring const& formatId) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->Contains(get_abi(formatId), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetDataAsync(param::hstring const& formatId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetDataAsync(get_abi(formatId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetTextAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetTextAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetTextAsync(param::hstring const& formatId) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetCustomTextAsync(get_abi(formatId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetUriAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetUriAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetHtmlFormatAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetHtmlFormatAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::Streams::RandomAccessStreamReference>> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetResourceMapAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::Streams::RandomAccessStreamReference>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetResourceMapAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetRtfAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetRtfAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetBitmapAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetBitmapAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetStorageItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetStorageItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView2<D>::GetApplicationLinkAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView2)->GetApplicationLinkAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView2<D>::GetWebLinkAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView2)->GetWebLinkAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView3)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>::RequestAccessAsync(param::hstring const& enterpriseId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView3)->RequestAccessWithEnterpriseIdAsync(get_abi(enterpriseId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>::UnlockAndAssumeEnterpriseIdentity() const
{
    Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView3)->UnlockAndAssumeEnterpriseIdentity(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataPackageView4<D>::SetAcceptedFormatId(param::hstring const& formatId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataPackageView4)->SetAcceptedFormatId(get_abi(formatId)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataProviderDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataProviderDeferral)->Complete());
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::FormatId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->get_FormatId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataProviderDeferral consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::GetDeferral() const
{
    Windows::ApplicationModel::DataTransfer::DataProviderDeferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::SetData(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->SetData(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackage consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::Data() const
{
    Windows::ApplicationModel::DataTransfer::DataPackage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequest)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::Data(Windows::ApplicationModel::DataTransfer::DataPackage const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequest)->put_Data(get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequest)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::FailWithDisplayText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequest)->FailWithDisplayText(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataRequestDeferral consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::GetDeferral() const
{
    Windows::ApplicationModel::DataTransfer::DataRequestDeferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequest)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequestDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataRequest consume_Windows_ApplicationModel_DataTransfer_IDataRequestedEventArgs<D>::Request() const
{
    Windows::ApplicationModel::DataTransfer::DataRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManager)->add_DataRequested(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested_revoker consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, DataRequested_revoker>(this, DataRequested(eventHandler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManager)->remove_DataRequested(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManager)->add_TargetApplicationChosen(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen_revoker consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, TargetApplicationChosen_revoker>(this, TargetApplicationChosen(eventHandler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManager)->remove_TargetApplicationChosen(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManager2)->add_ShareProvidersRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested_revoker consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ShareProvidersRequested_revoker>(this, ShareProvidersRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManager2)->remove_ShareProvidersRequested(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics<D>::ShowShareUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics)->ShowShareUI());
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataTransferManager consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::DataTransfer::DataTransferManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics)->GetForCurrentView(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics2<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2)->IsSupported(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics3<D>::ShowShareUI(Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3)->ShowShareUIWithOptions(get_abi(options)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IHtmlFormatHelperStatics<D>::GetStaticFragment(param::hstring const& htmlFormat) const
{
    hstring htmlFragment{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics)->GetStaticFragment(get_abi(htmlFormat), put_abi(htmlFragment)));
    return htmlFragment;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IHtmlFormatHelperStatics<D>::CreateHtmlFormat(param::hstring const& htmlFragment) const
{
    hstring htmlFormat{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics)->CreateHtmlFormat(get_abi(htmlFragment), put_abi(htmlFormat)));
    return htmlFormat;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs<D>::Operation() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs)->get_Operation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs2<D>::AcceptedFormatId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2)->get_AcceptedFormatId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::ShareTargetInfo consume_Windows_ApplicationModel_DataTransfer_IShareCompletedEventArgs<D>::ShareTarget() const
{
    Windows::ApplicationModel::DataTransfer::ShareTargetInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs)->get_ShareTarget(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvider)->get_Title(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::DisplayIcon() const
{
    Windows::Storage::Streams::RandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvider)->get_DisplayIcon(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvider)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::Tag() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvider)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::Tag(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvider)->put_Tag(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::DataTransfer::ShareProvider consume_Windows_ApplicationModel_DataTransfer_IShareProviderFactory<D>::Create(param::hstring const& title, Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, Windows::UI::Color const& backgroundColor, Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler) const
{
    Windows::ApplicationModel::DataTransfer::ShareProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProviderFactory)->Create(get_abi(title), get_abi(displayIcon), get_abi(backgroundColor), get_abi(handler), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>::Data() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProviderOperation)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::ShareProvider consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>::Provider() const
{
    Windows::ApplicationModel::DataTransfer::ShareProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProviderOperation)->get_Provider(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProviderOperation)->ReportCompleted());
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::DataTransfer::ShareProvider> consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>::Providers() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::DataTransfer::ShareProvider> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs)->get_Providers(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>::Data() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IShareTargetInfo<D>::AppUserModelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareTargetInfo)->get_AppUserModelId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::ShareProvider consume_Windows_ApplicationModel_DataTransfer_IShareTargetInfo<D>::ShareProvider() const
{
    Windows::ApplicationModel::DataTransfer::ShareProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareTargetInfo)->get_ShareProvider(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::ShareUITheme consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::Theme() const
{
    Windows::ApplicationModel::DataTransfer::ShareUITheme value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareUIOptions)->get_Theme(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::Theme(Windows::ApplicationModel::DataTransfer::ShareUITheme const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareUIOptions)->put_Theme(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Rect> consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::SelectionRect() const
{
    Windows::Foundation::IReference<Windows::Foundation::Rect> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareUIOptions)->get_SelectionRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::SelectionRect(optional<Windows::Foundation::Rect> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IShareUIOptions)->put_SelectionRect(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>::AddFile(Windows::Storage::IStorageFile const& file) const
{
    hstring outToken{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics)->AddFile(get_abi(file), put_abi(outToken)));
    return outToken;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>::RedeemTokenForFileAsync(param::hstring const& token) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics)->RedeemTokenForFileAsync(get_abi(token), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>::RemoveFile(param::hstring const& token) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics)->RemoveFile(get_abi(token)));
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Text(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Uri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Html() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Html(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Rtf() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Rtf(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Bitmap() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Bitmap(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::StorageItems() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_StorageItems(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics2<D>::WebLink() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2)->get_WebLink(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics2<D>::ApplicationLink() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2)->get_ApplicationLink(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics3<D>::UserActivityJsonArray() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3)->get_UserActivityJsonArray(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_DataTransfer_ITargetApplicationChosenEventArgs<D>::ApplicationName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs)->get_ApplicationName(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::ApplicationModel::DataTransfer::DataProviderHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::ApplicationModel::DataTransfer::DataProviderHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::ApplicationModel::DataTransfer::DataProviderHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* request) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataProviderRequest const*>(&request));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::ApplicationModel::DataTransfer::ShareProviderHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::ApplicationModel::DataTransfer::ShareProviderHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::ApplicationModel::DataTransfer::ShareProviderHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* operation) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::ShareProviderOperation const*>(&operation));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IClipboardContentOptions> : produce_base<D, Windows::ApplicationModel::DataTransfer::IClipboardContentOptions>
{
    int32_t WINRT_CALL get_IsRoamable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRoamable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRoamable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamable, WINRT_WRAP(void), bool);
            this->shim().IsRoamable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAllowedInHistory(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAllowedInHistory, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAllowedInHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAllowedInHistory(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAllowedInHistory, WINRT_WRAP(void), bool);
            this->shim().IsAllowedInHistory(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingFormats, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().RoamingFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HistoryFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoryFormats, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().HistoryFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs> : produce_base<D, Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem> : produce_base<D, Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult> : produce_base<D, Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IClipboardStatics> : produce_base<D, Windows::ApplicationModel::DataTransfer::IClipboardStatics>
{
    int32_t WINRT_CALL GetContent(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContent, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *result = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().GetContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContent(void* content) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContent, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackage const&);
            this->shim().SetContent(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackage const*>(&content));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Flush() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flush, WINRT_WRAP(void));
            this->shim().Flush();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContentChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ContentChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContentChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContentChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContentChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IClipboardStatics2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>
{
    int32_t WINRT_CALL GetHistoryItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHistoryItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>>(this->shim().GetHistoryItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearHistory(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearHistory, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ClearHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteItemFromHistory(void* item, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteItemFromHistory, WINRT_WRAP(bool), Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const&);
            *result = detach_from<bool>(this->shim().DeleteItemFromHistory(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHistoryItemAsContent(void* item, Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHistoryItemAsContent, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus), Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const&);
            *result = detach_from<Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus>(this->shim().SetHistoryItemAsContent(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsHistoryEnabled(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoryEnabled, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsHistoryEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsRoamingEnabled(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoamingEnabled, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsRoamingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentWithOptions(void* content, void* options, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentWithOptions, WINRT_WRAP(bool), Windows::ApplicationModel::DataTransfer::DataPackage const&, Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const&);
            *result = detach_from<bool>(this->shim().SetContentWithOptions(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackage const*>(&content), *reinterpret_cast<Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_HistoryChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoryChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HistoryChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HistoryChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HistoryChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HistoryChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RoamingEnabledChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RoamingEnabledChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RoamingEnabledChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RoamingEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RoamingEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HistoryEnabledChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoryEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().HistoryEnabledChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HistoryEnabledChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HistoryEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HistoryEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackage> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackage>
{
    int32_t WINRT_CALL GetView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetView, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().GetView());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackagePropertySet));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackagePropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedOperation, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().RequestedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedOperation, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackageOperation const&);
            this->shim().RequestedOperation(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OperationCompleted(void* handler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().OperationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OperationCompleted(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OperationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OperationCompleted(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_Destroyed(void* handler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Destroyed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().Destroyed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Destroyed(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Destroyed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Destroyed(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL SetData(void* formatId, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetData, WINRT_WRAP(void), hstring const&, Windows::Foundation::IInspectable const&);
            this->shim().SetData(*reinterpret_cast<hstring const*>(&formatId), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDataProvider(void* formatId, void* delayRenderer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDataProvider, WINRT_WRAP(void), hstring const&, Windows::ApplicationModel::DataTransfer::DataProviderHandler const&);
            this->shim().SetDataProvider(*reinterpret_cast<hstring const*>(&formatId), *reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataProviderHandler const*>(&delayRenderer));
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

    int32_t WINRT_CALL SetUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SetUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHtmlFormat(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHtmlFormat, WINRT_WRAP(void), hstring const&);
            this->shim().SetHtmlFormat(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceMap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceMap, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::Storage::Streams::RandomAccessStreamReference>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ResourceMap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRtf(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRtf, WINRT_WRAP(void), hstring const&);
            this->shim().SetRtf(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBitmap(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBitmap, WINRT_WRAP(void), Windows::Storage::Streams::RandomAccessStreamReference const&);
            this->shim().SetBitmap(*reinterpret_cast<Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStorageItemsReadOnly(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStorageItems, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const&);
            this->shim().SetStorageItems(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStorageItems(void* value, bool readOnly) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStorageItems, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const&, bool);
            this->shim().SetStorageItems(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::IStorageItem> const*>(&value), readOnly);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackage2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackage2>
{
    int32_t WINRT_CALL SetApplicationLink(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetApplicationLink, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SetApplicationLink(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetWebLink(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetWebLink, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SetWebLink(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackage3> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackage3>
{
    int32_t WINRT_CALL add_ShareCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShareCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ShareCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ShareCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ShareCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ShareCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FileTypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileTypes, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().FileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ApplicationName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationName, WINRT_WRAP(void), hstring const&);
            this->shim().ApplicationName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationListingUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationListingUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ApplicationListingUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ApplicationListingUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationListingUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ApplicationListingUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2>
{
    int32_t WINRT_CALL get_ContentSourceWebLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceWebLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentSourceWebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentSourceWebLink(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceWebLink, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ContentSourceWebLink(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentSourceApplicationLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceApplicationLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentSourceApplicationLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentSourceApplicationLink(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceApplicationLink, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ContentSourceApplicationLink(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PackageFamilyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(void), hstring const&);
            this->shim().PackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square30x30Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square30x30Logo, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Square30x30Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Square30x30Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square30x30Logo, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Square30x30Logo(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogoBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoBackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LogoBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LogoBackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoBackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().LogoBackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3>
{
    int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnterpriseId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(void), hstring const&);
            this->shim().EnterpriseId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>
{
    int32_t WINRT_CALL get_ContentSourceUserActivityJson(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceUserActivityJson, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentSourceUserActivityJson());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentSourceUserActivityJson(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceUserActivityJson, WINRT_WRAP(void), hstring const&);
            this->shim().ContentSourceUserActivityJson(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FileTypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileTypes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationListingUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationListingUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ApplicationListingUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2>
{
    int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentSourceWebLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceWebLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentSourceWebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentSourceApplicationLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceApplicationLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ContentSourceApplicationLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square30x30Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square30x30Logo, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Square30x30Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogoBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoBackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LogoBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3>
{
    int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4>
{
    int32_t WINRT_CALL get_ContentSourceUserActivityJson(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSourceUserActivityJson, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentSourceUserActivityJson());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5>
{
    int32_t WINRT_CALL get_IsFromRoamingClipboard(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFromRoamingClipboard, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFromRoamingClipboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackageView> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackageView>
{
    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedOperation, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().RequestedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportOperationCompleted(Windows::ApplicationModel::DataTransfer::DataPackageOperation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportOperationCompleted, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackageOperation const&);
            this->shim().ReportOperationCompleted(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AvailableFormats(void** formatIds) noexcept final
    {
        try
        {
            *formatIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *formatIds = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AvailableFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Contains(void* formatId, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contains, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().Contains(*reinterpret_cast<hstring const*>(&formatId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataAsync(void* formatId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable>>(this->shim().GetDataAsync(*reinterpret_cast<hstring const*>(&formatId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTextAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetTextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCustomTextAsync(void* formatId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetTextAsync(*reinterpret_cast<hstring const*>(&formatId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUriAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>>(this->shim().GetUriAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHtmlFormatAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHtmlFormatAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetHtmlFormatAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetResourceMapAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetResourceMapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::Streams::RandomAccessStreamReference>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::Streams::RandomAccessStreamReference>>>(this->shim().GetResourceMapAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRtfAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRtfAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetRtfAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBitmapAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().GetBitmapAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStorageItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStorageItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>>(this->shim().GetStorageItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackageView2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackageView2>
{
    int32_t WINRT_CALL GetApplicationLinkAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetApplicationLinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>>(this->shim().GetApplicationLinkAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWebLinkAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWebLinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri>>(this->shim().GetWebLinkAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackageView3> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackageView3>
{
    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessWithEnterpriseIdAsync(void* enterpriseId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync(*reinterpret_cast<hstring const*>(&enterpriseId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnlockAndAssumeEnterpriseIdentity(Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnlockAndAssumeEnterpriseIdentity, WINRT_WRAP(Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult));
            *result = detach_from<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>(this->shim().UnlockAndAssumeEnterpriseIdentity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataPackageView4> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataPackageView4>
{
    int32_t WINRT_CALL SetAcceptedFormatId(void* formatId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAcceptedFormatId, WINRT_WRAP(void), hstring const&);
            this->shim().SetAcceptedFormatId(*reinterpret_cast<hstring const*>(&formatId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataProviderDeferral> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataProviderDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataProviderRequest> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataProviderRequest>
{
    int32_t WINRT_CALL get_FormatId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormatId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormatId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataProviderDeferral));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataProviderDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetData, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().SetData(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataRequest> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataRequest>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackage));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackage>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackage const&);
            this->shim().Data(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FailWithDisplayText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailWithDisplayText, WINRT_WRAP(void), hstring const&);
            this->shim().FailWithDisplayText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataRequestDeferral));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataRequestDeferral> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataRequestDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataRequest));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataTransferManager> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataTransferManager>
{
    int32_t WINRT_CALL add_DataRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().DataRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataRequested(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_TargetApplicationChosen(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetApplicationChosen, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().TargetApplicationChosen(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TargetApplicationChosen(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TargetApplicationChosen, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TargetApplicationChosen(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataTransferManager2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataTransferManager2>
{
    int32_t WINRT_CALL add_ShareProvidersRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShareProvidersRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ShareProvidersRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ShareProvidersRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ShareProvidersRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ShareProvidersRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>
{
    int32_t WINRT_CALL ShowShareUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowShareUI, WINRT_WRAP(void));
            this->shim().ShowShareUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataTransferManager));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataTransferManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>
{
    int32_t WINRT_CALL IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3> : produce_base<D, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>
{
    int32_t WINRT_CALL ShowShareUIWithOptions(void* options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowShareUI, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::ShareUIOptions const&);
            this->shim().ShowShareUI(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::ShareUIOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics> : produce_base<D, Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>
{
    int32_t WINRT_CALL GetStaticFragment(void* htmlFormat, void** htmlFragment) noexcept final
    {
        try
        {
            *htmlFragment = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStaticFragment, WINRT_WRAP(hstring), hstring const&);
            *htmlFragment = detach_from<hstring>(this->shim().GetStaticFragment(*reinterpret_cast<hstring const*>(&htmlFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateHtmlFormat(void* htmlFragment, void** htmlFormat) noexcept final
    {
        try
        {
            *htmlFormat = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHtmlFormat, WINRT_WRAP(hstring), hstring const&);
            *htmlFormat = detach_from<hstring>(this->shim().CreateHtmlFormat(*reinterpret_cast<hstring const*>(&htmlFragment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs> : produce_base<D, Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs>
{
    int32_t WINRT_CALL get_Operation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Operation, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().Operation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>
{
    int32_t WINRT_CALL get_AcceptedFormatId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptedFormatId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AcceptedFormatId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs>
{
    int32_t WINRT_CALL get_ShareTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShareTarget, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::ShareTargetInfo));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::ShareTargetInfo>(this->shim().ShareTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareProvider> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareProvider>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayIcon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayIcon, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().DisplayIcon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Tag(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareProviderFactory> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareProviderFactory>
{
    int32_t WINRT_CALL Create(void* title, void* displayIcon, struct struct_Windows_UI_Color backgroundColor, void* handler, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::ShareProvider), hstring const&, Windows::Storage::Streams::RandomAccessStreamReference const&, Windows::UI::Color const&, Windows::ApplicationModel::DataTransfer::ShareProviderHandler const&);
            *result = detach_from<Windows::ApplicationModel::DataTransfer::ShareProvider>(this->shim().Create(*reinterpret_cast<hstring const*>(&title), *reinterpret_cast<Windows::Storage::Streams::RandomAccessStreamReference const*>(&displayIcon), *reinterpret_cast<Windows::UI::Color const*>(&backgroundColor), *reinterpret_cast<Windows::ApplicationModel::DataTransfer::ShareProviderHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareProviderOperation> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareProviderOperation>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Provider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Provider, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::ShareProvider));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::ShareProvider>(this->shim().Provider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs>
{
    int32_t WINRT_CALL get_Providers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Providers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::DataTransfer::ShareProvider>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::DataTransfer::ShareProvider>>(this->shim().Providers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareTargetInfo> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareTargetInfo>
{
    int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppUserModelId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShareProvider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShareProvider, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::ShareProvider));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::ShareProvider>(this->shim().ShareProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IShareUIOptions> : produce_base<D, Windows::ApplicationModel::DataTransfer::IShareUIOptions>
{
    int32_t WINRT_CALL get_Theme(Windows::ApplicationModel::DataTransfer::ShareUITheme* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Theme, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::ShareUITheme));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::ShareUITheme>(this->shim().Theme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Theme(Windows::ApplicationModel::DataTransfer::ShareUITheme value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Theme, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::ShareUITheme const&);
            this->shim().Theme(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::ShareUITheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionRect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionRect, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Rect>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Rect>>(this->shim().SelectionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectionRect(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionRect, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Rect> const&);
            this->shim().SelectionRect(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics> : produce_base<D, Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>
{
    int32_t WINRT_CALL AddFile(void* file, void** outToken) noexcept final
    {
        try
        {
            *outToken = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddFile, WINRT_WRAP(hstring), Windows::Storage::IStorageFile const&);
            *outToken = detach_from<hstring>(this->shim().AddFile(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RedeemTokenForFileAsync(void* token, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedeemTokenForFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().RedeemTokenForFileAsync(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveFile(void* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveFile, WINRT_WRAP(void), hstring const&);
            this->shim().RemoveFile(*reinterpret_cast<hstring const*>(&token));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics> : produce_base<D, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>
{
    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Html(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Html, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Html());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rtf(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rtf, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rtf());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitmap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitmap, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Bitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorageItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageItems, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StorageItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2> : produce_base<D, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>
{
    int32_t WINRT_CALL get_WebLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebLink, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationLink, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3> : produce_base<D, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>
{
    int32_t WINRT_CALL get_UserActivityJsonArray(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserActivityJsonArray, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserActivityJsonArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs> : produce_base<D, Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs>
{
    int32_t WINRT_CALL get_ApplicationName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer {

inline Windows::ApplicationModel::DataTransfer::DataPackageView Clipboard::GetContent()
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>([&](auto&& f) { return f.GetContent(); });
}

inline void Clipboard::SetContent(Windows::ApplicationModel::DataTransfer::DataPackage const& content)
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>([&](auto&& f) { return f.SetContent(content); });
}

inline void Clipboard::Flush()
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>([&](auto&& f) { return f.Flush(); });
}

inline void Clipboard::Clear()
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>([&](auto&& f) { return f.Clear(); });
}

inline winrt::event_token Clipboard::ContentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>([&](auto&& f) { return f.ContentChanged(handler); });
}

inline Clipboard::ContentChanged_revoker Clipboard::ContentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>();
    return { f, f.ContentChanged(handler) };
}

inline void Clipboard::ContentChanged(winrt::event_token const& token)
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics>([&](auto&& f) { return f.ContentChanged(token); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> Clipboard::GetHistoryItemsAsync()
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.GetHistoryItemsAsync(); });
}

inline bool Clipboard::ClearHistory()
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.ClearHistory(); });
}

inline bool Clipboard::DeleteItemFromHistory(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.DeleteItemFromHistory(item); });
}

inline Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus Clipboard::SetHistoryItemAsContent(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.SetHistoryItemAsContent(item); });
}

inline bool Clipboard::IsHistoryEnabled()
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.IsHistoryEnabled(); });
}

inline bool Clipboard::IsRoamingEnabled()
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.IsRoamingEnabled(); });
}

inline bool Clipboard::SetContentWithOptions(Windows::ApplicationModel::DataTransfer::DataPackage const& content, Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.SetContentWithOptions(content, options); });
}

inline winrt::event_token Clipboard::HistoryChanged(Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.HistoryChanged(handler); });
}

inline Clipboard::HistoryChanged_revoker Clipboard::HistoryChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler)
{
    auto f = get_activation_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>();
    return { f, f.HistoryChanged(handler) };
}

inline void Clipboard::HistoryChanged(winrt::event_token const& token)
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.HistoryChanged(token); });
}

inline winrt::event_token Clipboard::RoamingEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.RoamingEnabledChanged(handler); });
}

inline Clipboard::RoamingEnabledChanged_revoker Clipboard::RoamingEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>();
    return { f, f.RoamingEnabledChanged(handler) };
}

inline void Clipboard::RoamingEnabledChanged(winrt::event_token const& token)
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.RoamingEnabledChanged(token); });
}

inline winrt::event_token Clipboard::HistoryEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.HistoryEnabledChanged(handler); });
}

inline Clipboard::HistoryEnabledChanged_revoker Clipboard::HistoryEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>();
    return { f, f.HistoryEnabledChanged(handler) };
}

inline void Clipboard::HistoryEnabledChanged(winrt::event_token const& token)
{
    impl::call_factory<Clipboard, Windows::ApplicationModel::DataTransfer::IClipboardStatics2>([&](auto&& f) { return f.HistoryEnabledChanged(token); });
}

inline ClipboardContentOptions::ClipboardContentOptions() :
    ClipboardContentOptions(impl::call_factory<ClipboardContentOptions>([](auto&& f) { return f.template ActivateInstance<ClipboardContentOptions>(); }))
{}

inline DataPackage::DataPackage() :
    DataPackage(impl::call_factory<DataPackage>([](auto&& f) { return f.template ActivateInstance<DataPackage>(); }))
{}

inline void DataTransferManager::ShowShareUI()
{
    impl::call_factory<DataTransferManager, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>([&](auto&& f) { return f.ShowShareUI(); });
}

inline Windows::ApplicationModel::DataTransfer::DataTransferManager DataTransferManager::GetForCurrentView()
{
    return impl::call_factory<DataTransferManager, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline bool DataTransferManager::IsSupported()
{
    return impl::call_factory<DataTransferManager, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>([&](auto&& f) { return f.IsSupported(); });
}

inline void DataTransferManager::ShowShareUI(Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options)
{
    impl::call_factory<DataTransferManager, Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>([&](auto&& f) { return f.ShowShareUI(options); });
}

inline hstring HtmlFormatHelper::GetStaticFragment(param::hstring const& htmlFormat)
{
    return impl::call_factory<HtmlFormatHelper, Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>([&](auto&& f) { return f.GetStaticFragment(htmlFormat); });
}

inline hstring HtmlFormatHelper::CreateHtmlFormat(param::hstring const& htmlFragment)
{
    return impl::call_factory<HtmlFormatHelper, Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>([&](auto&& f) { return f.CreateHtmlFormat(htmlFragment); });
}

inline ShareProvider::ShareProvider(param::hstring const& title, Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, Windows::UI::Color const& backgroundColor, Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler) :
    ShareProvider(impl::call_factory<ShareProvider, Windows::ApplicationModel::DataTransfer::IShareProviderFactory>([&](auto&& f) { return f.Create(title, displayIcon, backgroundColor, handler); }))
{}

inline ShareUIOptions::ShareUIOptions() :
    ShareUIOptions(impl::call_factory<ShareUIOptions>([](auto&& f) { return f.template ActivateInstance<ShareUIOptions>(); }))
{}

inline hstring SharedStorageAccessManager::AddFile(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<SharedStorageAccessManager, Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>([&](auto&& f) { return f.AddFile(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> SharedStorageAccessManager::RedeemTokenForFileAsync(param::hstring const& token)
{
    return impl::call_factory<SharedStorageAccessManager, Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>([&](auto&& f) { return f.RedeemTokenForFileAsync(token); });
}

inline void SharedStorageAccessManager::RemoveFile(param::hstring const& token)
{
    impl::call_factory<SharedStorageAccessManager, Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>([&](auto&& f) { return f.RemoveFile(token); });
}

inline hstring StandardDataFormats::Text()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>([&](auto&& f) { return f.Text(); });
}

inline hstring StandardDataFormats::Uri()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>([&](auto&& f) { return f.Uri(); });
}

inline hstring StandardDataFormats::Html()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>([&](auto&& f) { return f.Html(); });
}

inline hstring StandardDataFormats::Rtf()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>([&](auto&& f) { return f.Rtf(); });
}

inline hstring StandardDataFormats::Bitmap()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>([&](auto&& f) { return f.Bitmap(); });
}

inline hstring StandardDataFormats::StorageItems()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>([&](auto&& f) { return f.StorageItems(); });
}

inline hstring StandardDataFormats::WebLink()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>([&](auto&& f) { return f.WebLink(); });
}

inline hstring StandardDataFormats::ApplicationLink()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>([&](auto&& f) { return f.ApplicationLink(); });
}

inline hstring StandardDataFormats::UserActivityJsonArray()
{
    return impl::call_factory<StandardDataFormats, Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>([&](auto&& f) { return f.UserActivityJsonArray(); });
}

template <typename L> DataProviderHandler::DataProviderHandler(L handler) :
    DataProviderHandler(impl::make_delegate<DataProviderHandler>(std::forward<L>(handler)))
{}

template <typename F> DataProviderHandler::DataProviderHandler(F* handler) :
    DataProviderHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DataProviderHandler::DataProviderHandler(O* object, M method) :
    DataProviderHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DataProviderHandler::DataProviderHandler(com_ptr<O>&& object, M method) :
    DataProviderHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DataProviderHandler::DataProviderHandler(weak_ref<O>&& object, M method) :
    DataProviderHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DataProviderHandler::operator()(Windows::ApplicationModel::DataTransfer::DataProviderRequest const& request) const
{
    check_hresult((*(impl::abi_t<DataProviderHandler>**)this)->Invoke(get_abi(request)));
}

template <typename L> ShareProviderHandler::ShareProviderHandler(L handler) :
    ShareProviderHandler(impl::make_delegate<ShareProviderHandler>(std::forward<L>(handler)))
{}

template <typename F> ShareProviderHandler::ShareProviderHandler(F* handler) :
    ShareProviderHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ShareProviderHandler::ShareProviderHandler(O* object, M method) :
    ShareProviderHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ShareProviderHandler::ShareProviderHandler(com_ptr<O>&& object, M method) :
    ShareProviderHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ShareProviderHandler::ShareProviderHandler(weak_ref<O>&& object, M method) :
    ShareProviderHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ShareProviderHandler::operator()(Windows::ApplicationModel::DataTransfer::ShareProviderOperation const& operation) const
{
    check_hresult((*(impl::abi_t<ShareProviderHandler>**)this)->Invoke(get_abi(operation)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProvider> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareProvider> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProviderFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareProviderFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::Clipboard> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::Clipboard> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataPackage> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySet> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySet> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataProviderDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataProviderDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataProviderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataProviderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataRequestDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataRequestDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::HtmlFormatHelper> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::HtmlFormatHelper> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTargetInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareTargetInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::SharedStorageAccessManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::SharedStorageAccessManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::StandardDataFormats> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::StandardDataFormats> {};
template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> {};

}
