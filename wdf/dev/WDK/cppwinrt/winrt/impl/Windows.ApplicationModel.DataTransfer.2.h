// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Security.EnterpriseData.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer {

struct DataProviderHandler : Windows::Foundation::IUnknown
{
    DataProviderHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> DataProviderHandler(L lambda);
    template <typename F> DataProviderHandler(F* function);
    template <typename O, typename M> DataProviderHandler(O* object, M method);
    template <typename O, typename M> DataProviderHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> DataProviderHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::ApplicationModel::DataTransfer::DataProviderRequest const& request) const;
};

struct ShareProviderHandler : Windows::Foundation::IUnknown
{
    ShareProviderHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> ShareProviderHandler(L lambda);
    template <typename F> ShareProviderHandler(F* function);
    template <typename O, typename M> ShareProviderHandler(O* object, M method);
    template <typename O, typename M> ShareProviderHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> ShareProviderHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::ApplicationModel::DataTransfer::ShareProviderOperation const& operation) const;
};

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer {

struct Clipboard
{
    Clipboard() = delete;
    static Windows::ApplicationModel::DataTransfer::DataPackageView GetContent();
    static void SetContent(Windows::ApplicationModel::DataTransfer::DataPackage const& content);
    static void Flush();
    static void Clear();
    static winrt::event_token ContentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using ContentChanged_revoker = impl::factory_event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics>::remove_ContentChanged>;
    static ContentChanged_revoker ContentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void ContentChanged(winrt::event_token const& token);
    static Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> GetHistoryItemsAsync();
    static bool ClearHistory();
    static bool DeleteItemFromHistory(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item);
    static Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus SetHistoryItemAsContent(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item);
    static bool IsHistoryEnabled();
    static bool IsRoamingEnabled();
    static bool SetContentWithOptions(Windows::ApplicationModel::DataTransfer::DataPackage const& content, Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options);
    static winrt::event_token HistoryChanged(Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler);
    using HistoryChanged_revoker = impl::factory_event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_HistoryChanged>;
    static HistoryChanged_revoker HistoryChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler);
    static void HistoryChanged(winrt::event_token const& token);
    static winrt::event_token RoamingEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RoamingEnabledChanged_revoker = impl::factory_event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_RoamingEnabledChanged>;
    static RoamingEnabledChanged_revoker RoamingEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RoamingEnabledChanged(winrt::event_token const& token);
    static winrt::event_token HistoryEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using HistoryEnabledChanged_revoker = impl::factory_event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_HistoryEnabledChanged>;
    static HistoryEnabledChanged_revoker HistoryEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void HistoryEnabledChanged(winrt::event_token const& token);
};

struct WINRT_EBO ClipboardContentOptions :
    Windows::ApplicationModel::DataTransfer::IClipboardContentOptions
{
    ClipboardContentOptions(std::nullptr_t) noexcept {}
    ClipboardContentOptions();
};

struct WINRT_EBO ClipboardHistoryChangedEventArgs :
    Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs
{
    ClipboardHistoryChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ClipboardHistoryItem :
    Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem
{
    ClipboardHistoryItem(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ClipboardHistoryItemsResult :
    Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult
{
    ClipboardHistoryItemsResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataPackage :
    Windows::ApplicationModel::DataTransfer::IDataPackage,
    impl::require<DataPackage, Windows::ApplicationModel::DataTransfer::IDataPackage2, Windows::ApplicationModel::DataTransfer::IDataPackage3>
{
    DataPackage(std::nullptr_t) noexcept {}
    DataPackage();
};

struct WINRT_EBO DataPackagePropertySet :
    Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet,
    impl::require<DataPackagePropertySet, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>
{
    DataPackagePropertySet(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataPackagePropertySetView :
    Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView,
    impl::require<DataPackagePropertySetView, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4, Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>>, Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>
{
    DataPackagePropertySetView(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataPackageView :
    Windows::ApplicationModel::DataTransfer::IDataPackageView,
    impl::require<DataPackageView, Windows::ApplicationModel::DataTransfer::IDataPackageView2, Windows::ApplicationModel::DataTransfer::IDataPackageView3, Windows::ApplicationModel::DataTransfer::IDataPackageView4>
{
    DataPackageView(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataProviderDeferral :
    Windows::ApplicationModel::DataTransfer::IDataProviderDeferral
{
    DataProviderDeferral(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataProviderRequest :
    Windows::ApplicationModel::DataTransfer::IDataProviderRequest
{
    DataProviderRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataRequest :
    Windows::ApplicationModel::DataTransfer::IDataRequest
{
    DataRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataRequestDeferral :
    Windows::ApplicationModel::DataTransfer::IDataRequestDeferral
{
    DataRequestDeferral(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataRequestedEventArgs :
    Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs
{
    DataRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DataTransferManager :
    Windows::ApplicationModel::DataTransfer::IDataTransferManager,
    impl::require<DataTransferManager, Windows::ApplicationModel::DataTransfer::IDataTransferManager2>
{
    DataTransferManager(std::nullptr_t) noexcept {}
    static void ShowShareUI();
    static Windows::ApplicationModel::DataTransfer::DataTransferManager GetForCurrentView();
    static bool IsSupported();
    static void ShowShareUI(Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options);
};

struct HtmlFormatHelper
{
    HtmlFormatHelper() = delete;
    static hstring GetStaticFragment(param::hstring const& htmlFormat);
    static hstring CreateHtmlFormat(param::hstring const& htmlFragment);
};

struct WINRT_EBO OperationCompletedEventArgs :
    Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs,
    impl::require<OperationCompletedEventArgs, Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>
{
    OperationCompletedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShareCompletedEventArgs :
    Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs
{
    ShareCompletedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShareProvider :
    Windows::ApplicationModel::DataTransfer::IShareProvider
{
    ShareProvider(std::nullptr_t) noexcept {}
    ShareProvider(param::hstring const& title, Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, Windows::UI::Color const& backgroundColor, Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler);
};

struct WINRT_EBO ShareProviderOperation :
    Windows::ApplicationModel::DataTransfer::IShareProviderOperation
{
    ShareProviderOperation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShareProvidersRequestedEventArgs :
    Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs
{
    ShareProvidersRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShareTargetInfo :
    Windows::ApplicationModel::DataTransfer::IShareTargetInfo
{
    ShareTargetInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShareUIOptions :
    Windows::ApplicationModel::DataTransfer::IShareUIOptions
{
    ShareUIOptions(std::nullptr_t) noexcept {}
    ShareUIOptions();
};

struct SharedStorageAccessManager
{
    SharedStorageAccessManager() = delete;
    static hstring AddFile(Windows::Storage::IStorageFile const& file);
    static Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> RedeemTokenForFileAsync(param::hstring const& token);
    static void RemoveFile(param::hstring const& token);
};

struct StandardDataFormats
{
    StandardDataFormats() = delete;
    static hstring Text();
    static hstring Uri();
    static hstring Html();
    static hstring Rtf();
    static hstring Bitmap();
    static hstring StorageItems();
    static hstring WebLink();
    static hstring ApplicationLink();
    static hstring UserActivityJsonArray();
};

struct WINRT_EBO TargetApplicationChosenEventArgs :
    Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs
{
    TargetApplicationChosenEventArgs(std::nullptr_t) noexcept {}
};

}
