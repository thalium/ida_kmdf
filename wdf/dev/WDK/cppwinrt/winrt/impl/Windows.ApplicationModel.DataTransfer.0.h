// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;
struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Security::EnterpriseData {

enum class ProtectionPolicyEvaluationResult;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;
struct IStorageItem;
struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;
struct RandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer {

enum class ClipboardHistoryItemsResultStatus : int32_t
{
    Success = 0,
    AccessDenied = 1,
    ClipboardHistoryDisabled = 2,
};

enum class DataPackageOperation : uint32_t
{
    None = 0x0,
    Copy = 0x1,
    Move = 0x2,
    Link = 0x4,
};

enum class SetHistoryItemAsContentStatus : int32_t
{
    Success = 0,
    AccessDenied = 1,
    ItemDeleted = 2,
};

enum class ShareUITheme : int32_t
{
    Default = 0,
    Light = 1,
    Dark = 2,
};

struct IClipboardContentOptions;
struct IClipboardHistoryChangedEventArgs;
struct IClipboardHistoryItem;
struct IClipboardHistoryItemsResult;
struct IClipboardStatics;
struct IClipboardStatics2;
struct IDataPackage;
struct IDataPackage2;
struct IDataPackage3;
struct IDataPackagePropertySet;
struct IDataPackagePropertySet2;
struct IDataPackagePropertySet3;
struct IDataPackagePropertySet4;
struct IDataPackagePropertySetView;
struct IDataPackagePropertySetView2;
struct IDataPackagePropertySetView3;
struct IDataPackagePropertySetView4;
struct IDataPackagePropertySetView5;
struct IDataPackageView;
struct IDataPackageView2;
struct IDataPackageView3;
struct IDataPackageView4;
struct IDataProviderDeferral;
struct IDataProviderRequest;
struct IDataRequest;
struct IDataRequestDeferral;
struct IDataRequestedEventArgs;
struct IDataTransferManager;
struct IDataTransferManager2;
struct IDataTransferManagerStatics;
struct IDataTransferManagerStatics2;
struct IDataTransferManagerStatics3;
struct IHtmlFormatHelperStatics;
struct IOperationCompletedEventArgs;
struct IOperationCompletedEventArgs2;
struct IShareCompletedEventArgs;
struct IShareProvider;
struct IShareProviderFactory;
struct IShareProviderOperation;
struct IShareProvidersRequestedEventArgs;
struct IShareTargetInfo;
struct IShareUIOptions;
struct ISharedStorageAccessManagerStatics;
struct IStandardDataFormatsStatics;
struct IStandardDataFormatsStatics2;
struct IStandardDataFormatsStatics3;
struct ITargetApplicationChosenEventArgs;
struct Clipboard;
struct ClipboardContentOptions;
struct ClipboardHistoryChangedEventArgs;
struct ClipboardHistoryItem;
struct ClipboardHistoryItemsResult;
struct DataPackage;
struct DataPackagePropertySet;
struct DataPackagePropertySetView;
struct DataPackageView;
struct DataProviderDeferral;
struct DataProviderRequest;
struct DataRequest;
struct DataRequestDeferral;
struct DataRequestedEventArgs;
struct DataTransferManager;
struct HtmlFormatHelper;
struct OperationCompletedEventArgs;
struct ShareCompletedEventArgs;
struct ShareProvider;
struct ShareProviderOperation;
struct ShareProvidersRequestedEventArgs;
struct ShareTargetInfo;
struct ShareUIOptions;
struct SharedStorageAccessManager;
struct StandardDataFormats;
struct TargetApplicationChosenEventArgs;
struct DataProviderHandler;
struct ShareProviderHandler;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::ApplicationModel::DataTransfer::DataPackageOperation> : std::true_type {};
template <> struct category<Windows::ApplicationModel::DataTransfer::IClipboardContentOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IClipboardStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackage>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackage2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackage3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackageView>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackageView2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackageView3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataPackageView4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataProviderDeferral>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataProviderRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataRequest>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataRequestDeferral>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataTransferManager>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataTransferManager2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareProvider>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareProviderFactory>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareProviderOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareTargetInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IShareUIOptions>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::Clipboard>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ClipboardContentOptions>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataPackage>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataPackagePropertySet>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataPackageView>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataProviderDeferral>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataProviderRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataRequest>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataRequestDeferral>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataTransferManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::HtmlFormatHelper>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareProvider>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareProviderOperation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareTargetInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareUIOptions>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::SharedStorageAccessManager>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::StandardDataFormats>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataPackageOperation>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareUITheme>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::DataProviderHandler>{ using type = delegate_category; };
template <> struct category<Windows::ApplicationModel::DataTransfer::ShareProviderHandler>{ using type = delegate_category; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IClipboardContentOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IClipboardContentOptions" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IClipboardHistoryChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IClipboardHistoryItem" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IClipboardHistoryItemsResult" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IClipboardStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IClipboardStatics" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IClipboardStatics2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackage>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackage" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackage2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackage2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackage3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackage3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySet" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySet2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySet3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySet4" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySetView" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySetView2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySetView3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySetView4" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackagePropertySetView5" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackageView>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackageView" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackageView2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackageView2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackageView3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackageView3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataPackageView4>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataPackageView4" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataProviderDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataProviderDeferral" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataProviderRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataProviderRequest" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataRequest" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataRequestDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataRequestDeferral" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataTransferManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataTransferManager" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataTransferManager2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataTransferManager2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataTransferManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataTransferManagerStatics2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IDataTransferManagerStatics3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IHtmlFormatHelperStatics" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IOperationCompletedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IOperationCompletedEventArgs2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareCompletedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareProvider>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareProvider" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareProviderFactory>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareProviderFactory" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareProviderOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareProviderOperation" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareProvidersRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareTargetInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareTargetInfo" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IShareUIOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IShareUIOptions" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ISharedStorageAccessManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IStandardDataFormatsStatics" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IStandardDataFormatsStatics2" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.IStandardDataFormatsStatics3" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ITargetApplicationChosenEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::Clipboard>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.Clipboard" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ClipboardContentOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ClipboardContentOptions" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ClipboardHistoryChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ClipboardHistoryItem" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataPackage>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataPackage" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataPackagePropertySet>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataPackagePropertySet" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataPackagePropertySetView" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataPackageView>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataPackageView" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataProviderDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataProviderDeferral" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataProviderRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataProviderRequest" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataRequest>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataRequest" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataRequestDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataRequestDeferral" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataTransferManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataTransferManager" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::HtmlFormatHelper>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.HtmlFormatHelper" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.OperationCompletedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareCompletedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareProvider>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareProvider" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareProviderOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareProviderOperation" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareProvidersRequestedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareTargetInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareTargetInfo" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareUIOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareUIOptions" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::SharedStorageAccessManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.SharedStorageAccessManager" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::StandardDataFormats>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.StandardDataFormats" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.TargetApplicationChosenEventArgs" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResultStatus" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataPackageOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataPackageOperation" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.SetHistoryItemAsContentStatus" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareUITheme>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareUITheme" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::DataProviderHandler>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.DataProviderHandler" }; };
template <> struct name<Windows::ApplicationModel::DataTransfer::ShareProviderHandler>{ static constexpr auto & value{ L"Windows.ApplicationModel.DataTransfer.ShareProviderHandler" }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IClipboardContentOptions>{ static constexpr guid value{ 0xE888A98C,0xAD4B,0x5447,{ 0xA0,0x56,0xAB,0x35,0x56,0x27,0x6D,0x2B } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs>{ static constexpr guid value{ 0xC0BE453F,0x8EA2,0x53CE,{ 0x9A,0xBA,0x8D,0x22,0x12,0x57,0x34,0x52 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem>{ static constexpr guid value{ 0x0173BD8A,0xAFFF,0x5C50,{ 0xAB,0x92,0x3D,0x19,0xF4,0x81,0xEC,0x58 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult>{ static constexpr guid value{ 0xE6DFDEE6,0x0EE2,0x52E3,{ 0x85,0x2B,0xF2,0x95,0xDB,0x65,0x93,0x9A } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IClipboardStatics>{ static constexpr guid value{ 0xC627E291,0x34E2,0x4963,{ 0x8E,0xED,0x93,0xCB,0xB0,0xEA,0x3D,0x70 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>{ static constexpr guid value{ 0xD2AC1B6A,0xD29F,0x554B,{ 0xB3,0x03,0xF0,0x45,0x23,0x45,0xFE,0x02 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackage>{ static constexpr guid value{ 0x61EBF5C7,0xEFEA,0x4346,{ 0x95,0x54,0x98,0x1D,0x7E,0x19,0x8F,0xFE } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackage2>{ static constexpr guid value{ 0x041C1FE9,0x2409,0x45E1,{ 0xA5,0x38,0x4C,0x53,0xEE,0xEE,0x04,0xA7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackage3>{ static constexpr guid value{ 0x88F31F5D,0x787B,0x4D32,{ 0x96,0x5A,0xA9,0x83,0x81,0x05,0xA0,0x56 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet>{ static constexpr guid value{ 0xCD1C93EB,0x4C4C,0x443A,{ 0xA8,0xD3,0xF5,0xC2,0x41,0xE9,0x16,0x89 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2>{ static constexpr guid value{ 0xEB505D4A,0x9800,0x46AA,{ 0xB1,0x81,0x7B,0x6F,0x0F,0x2B,0x91,0x9A } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3>{ static constexpr guid value{ 0x9E87FD9B,0x5205,0x401B,{ 0x87,0x4A,0x45,0x56,0x53,0xBD,0x39,0xE8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>{ static constexpr guid value{ 0x6390EBF5,0x1739,0x4C74,{ 0xB2,0x2F,0x86,0x5F,0xAB,0x5E,0x85,0x45 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView>{ static constexpr guid value{ 0xB94CEC01,0x0C1A,0x4C57,{ 0xBE,0x55,0x75,0xD0,0x12,0x89,0x73,0x5D } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2>{ static constexpr guid value{ 0x6054509B,0x8EBE,0x4FEB,{ 0x9C,0x1E,0x75,0xE6,0x9D,0xE5,0x4B,0x84 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3>{ static constexpr guid value{ 0xDB764CE5,0xD174,0x495C,{ 0x84,0xFC,0x1A,0x51,0xF6,0xAB,0x45,0xD7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4>{ static constexpr guid value{ 0x4474C80D,0xD16F,0x40AE,{ 0x95,0x80,0x6F,0x85,0x62,0xB9,0x42,0x35 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5>{ static constexpr guid value{ 0x6F0A9445,0x3760,0x50BB,{ 0x85,0x23,0xC4,0x20,0x2D,0xED,0x7D,0x78 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackageView>{ static constexpr guid value{ 0x7B840471,0x5900,0x4D85,{ 0xA9,0x0B,0x10,0xCB,0x85,0xFE,0x35,0x52 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackageView2>{ static constexpr guid value{ 0x40ECBA95,0x2450,0x4C1D,{ 0xB6,0xB4,0xED,0x45,0x46,0x3D,0xEE,0x9C } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackageView3>{ static constexpr guid value{ 0xD37771A8,0xDDAD,0x4288,{ 0x84,0x28,0xD1,0xCA,0xE3,0x94,0x12,0x8B } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataPackageView4>{ static constexpr guid value{ 0xDFE96F1F,0xE042,0x4433,{ 0xA0,0x9F,0x26,0xD6,0xFF,0xDA,0x8B,0x85 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataProviderDeferral>{ static constexpr guid value{ 0xC2CF2373,0x2D26,0x43D9,{ 0xB6,0x9D,0xDC,0xB8,0x6D,0x03,0xF6,0xDA } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataProviderRequest>{ static constexpr guid value{ 0xEBBC7157,0xD3C8,0x47DA,{ 0xAC,0xDE,0xF8,0x23,0x88,0xD5,0xF7,0x16 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataRequest>{ static constexpr guid value{ 0x4341AE3B,0xFC12,0x4E53,{ 0x8C,0x02,0xAC,0x71,0x4C,0x41,0x5A,0x27 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataRequestDeferral>{ static constexpr guid value{ 0x6DC4B89F,0x0386,0x4263,{ 0x87,0xC1,0xED,0x7D,0xCE,0x30,0x89,0x0E } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs>{ static constexpr guid value{ 0xCB8BA807,0x6AC5,0x43C9,{ 0x8A,0xC5,0x9B,0xA2,0x32,0x16,0x31,0x82 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataTransferManager>{ static constexpr guid value{ 0xA5CAEE9B,0x8708,0x49D1,{ 0x8D,0x36,0x67,0xD2,0x5A,0x8D,0xA0,0x0C } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataTransferManager2>{ static constexpr guid value{ 0x30AE7D71,0x8BA8,0x4C02,{ 0x8E,0x3F,0xDD,0xB2,0x3B,0x38,0x87,0x15 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>{ static constexpr guid value{ 0xA9DA01AA,0xE00E,0x4CFE,{ 0xAA,0x44,0x2D,0xD9,0x32,0xDC,0xA3,0xD8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>{ static constexpr guid value{ 0xC54EC2EC,0x9F97,0x4D63,{ 0x98,0x68,0x39,0x5E,0x27,0x1A,0xD8,0xF5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>{ static constexpr guid value{ 0x05845473,0x6C82,0x4F5C,{ 0xAC,0x23,0x62,0xE4,0x58,0x36,0x1F,0xAC } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>{ static constexpr guid value{ 0xE22E7749,0xDD70,0x446F,{ 0xAE,0xFC,0x61,0xCE,0xE5,0x9F,0x65,0x5E } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs>{ static constexpr guid value{ 0xE7AF329D,0x051D,0x4FAB,{ 0xB1,0xA9,0x47,0xFD,0x77,0xF7,0x0A,0x41 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>{ static constexpr guid value{ 0x858FA073,0x1E19,0x4105,{ 0xB2,0xF7,0xC8,0x47,0x88,0x08,0xD5,0x62 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs>{ static constexpr guid value{ 0x4574C442,0xF913,0x4F60,{ 0x9D,0xF7,0xCC,0x40,0x60,0xAB,0x19,0x16 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareProvider>{ static constexpr guid value{ 0x2FABE026,0x443E,0x4CDA,{ 0xAF,0x25,0x8D,0x81,0x07,0x0E,0xFD,0x80 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareProviderFactory>{ static constexpr guid value{ 0x172A174C,0xE79E,0x4F6D,{ 0xB0,0x7D,0x12,0x8F,0x46,0x9E,0x02,0x96 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareProviderOperation>{ static constexpr guid value{ 0x19CEF937,0xD435,0x4179,{ 0xB6,0xAF,0x14,0xE0,0x49,0x2B,0x69,0xF6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs>{ static constexpr guid value{ 0xF888F356,0xA3F8,0x4FCE,{ 0x85,0xE4,0x88,0x26,0xE6,0x3B,0xE7,0x99 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareTargetInfo>{ static constexpr guid value{ 0x385BE607,0xC6E8,0x4114,{ 0xB2,0x94,0x28,0xF3,0xBB,0x6F,0x99,0x04 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IShareUIOptions>{ static constexpr guid value{ 0x72FA8A80,0x342F,0x4D90,{ 0x95,0x51,0x2A,0xE0,0x4E,0x37,0x68,0x0C } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>{ static constexpr guid value{ 0xC6132ADA,0x34B1,0x4849,{ 0xBD,0x5F,0xD0,0x9F,0xEE,0x31,0x58,0xC5 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>{ static constexpr guid value{ 0x7ED681A1,0xA880,0x40C9,{ 0xB4,0xED,0x0B,0xEE,0x1E,0x15,0xF5,0x49 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>{ static constexpr guid value{ 0x42A254F4,0x9D76,0x42E8,{ 0x86,0x1B,0x47,0xC2,0x5D,0xD0,0xCF,0x71 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>{ static constexpr guid value{ 0x3B57B069,0x01D4,0x474C,{ 0x8B,0x5F,0xBC,0x8E,0x27,0xF3,0x8B,0x21 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs>{ static constexpr guid value{ 0xCA6FB8AC,0x2987,0x4EE3,{ 0x9C,0x54,0xD8,0xAF,0xBC,0xB8,0x6C,0x1D } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::DataProviderHandler>{ static constexpr guid value{ 0xE7ECD720,0xF2F4,0x4A2D,{ 0x92,0x0E,0x17,0x0A,0x2F,0x48,0x2A,0x27 } }; };
template <> struct guid_storage<Windows::ApplicationModel::DataTransfer::ShareProviderHandler>{ static constexpr guid value{ 0xE7F9D9BA,0xE1BA,0x4E4D,{ 0xBD,0x65,0xD4,0x38,0x45,0xD3,0x21,0x2F } }; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ClipboardContentOptions>{ using type = Windows::ApplicationModel::DataTransfer::IClipboardContentOptions; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs>{ using type = Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>{ using type = Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>{ using type = Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataPackage>{ using type = Windows::ApplicationModel::DataTransfer::IDataPackage; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataPackagePropertySet>{ using type = Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView>{ using type = Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataPackageView>{ using type = Windows::ApplicationModel::DataTransfer::IDataPackageView; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataProviderDeferral>{ using type = Windows::ApplicationModel::DataTransfer::IDataProviderDeferral; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataProviderRequest>{ using type = Windows::ApplicationModel::DataTransfer::IDataProviderRequest; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataRequest>{ using type = Windows::ApplicationModel::DataTransfer::IDataRequest; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataRequestDeferral>{ using type = Windows::ApplicationModel::DataTransfer::IDataRequestDeferral; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs>{ using type = Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::DataTransferManager>{ using type = Windows::ApplicationModel::DataTransfer::IDataTransferManager; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs>{ using type = Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs>{ using type = Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareProvider>{ using type = Windows::ApplicationModel::DataTransfer::IShareProvider; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareProviderOperation>{ using type = Windows::ApplicationModel::DataTransfer::IShareProviderOperation; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs>{ using type = Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareTargetInfo>{ using type = Windows::ApplicationModel::DataTransfer::IShareTargetInfo; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::ShareUIOptions>{ using type = Windows::ApplicationModel::DataTransfer::IShareUIOptions; };
template <> struct default_interface<Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs>{ using type = Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs; };

template <> struct abi<Windows::ApplicationModel::DataTransfer::IClipboardContentOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsRoamable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsRoamable(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAllowedInHistory(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsAllowedInHistory(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoamingFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HistoryFormats(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Items(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IClipboardStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetContent(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetContent(void* content) noexcept = 0;
    virtual int32_t WINRT_CALL Flush() noexcept = 0;
    virtual int32_t WINRT_CALL Clear() noexcept = 0;
    virtual int32_t WINRT_CALL add_ContentChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ContentChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetHistoryItemsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ClearHistory(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteItemFromHistory(void* item, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetHistoryItemAsContent(void* item, Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsHistoryEnabled(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsRoamingEnabled(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetContentWithOptions(void* content, void* options, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL add_HistoryChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_HistoryChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RoamingEnabledChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RoamingEnabledChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_HistoryEnabledChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_HistoryEnabledChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetView(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation value) noexcept = 0;
    virtual int32_t WINRT_CALL add_OperationCompleted(void* handler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_OperationCompleted(winrt::event_token eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_Destroyed(void* handler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Destroyed(winrt::event_token eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL SetData(void* formatId, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetDataProvider(void* formatId, void* delayRenderer) noexcept = 0;
    virtual int32_t WINRT_CALL SetText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetHtmlFormat(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceMap(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetRtf(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetBitmap(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetStorageItemsReadOnly(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetStorageItems(void* value, bool readOnly) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackage2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetApplicationLink(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetWebLink(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackage3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ShareCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ShareCompleted(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileTypes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ApplicationName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ApplicationName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ApplicationListingUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ApplicationListingUri(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentSourceWebLink(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentSourceWebLink(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentSourceApplicationLink(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentSourceApplicationLink(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PackageFamilyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Square30x30Logo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Square30x30Logo(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LogoBackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LogoBackgroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EnterpriseId(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentSourceUserActivityJson(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentSourceUserActivityJson(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileTypes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ApplicationName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ApplicationListingUri(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentSourceWebLink(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentSourceApplicationLink(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Square30x30Logo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LogoBackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentSourceUserActivityJson(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsFromRoamingClipboard(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackageView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportOperationCompleted(Windows::ApplicationModel::DataTransfer::DataPackageOperation value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AvailableFormats(void** formatIds) noexcept = 0;
    virtual int32_t WINRT_CALL Contains(void* formatId, bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDataAsync(void* formatId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetTextAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCustomTextAsync(void* formatId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetUriAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetHtmlFormatAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetResourceMapAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetRtfAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetBitmapAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStorageItemsAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackageView2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetApplicationLinkAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetWebLinkAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackageView3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessWithEnterpriseIdAsync(void* enterpriseId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UnlockAndAssumeEnterpriseIdentity(Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult* result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataPackageView4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetAcceptedFormatId(void* formatId) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataProviderDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataProviderRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FormatId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetData(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Data(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL FailWithDisplayText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataRequestDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataTransferManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_DataRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DataRequested(winrt::event_token eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_TargetApplicationChosen(void* eventHandler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TargetApplicationChosen(winrt::event_token eventCookie) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataTransferManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ShareProvidersRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ShareProvidersRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowShareUI() noexcept = 0;
    virtual int32_t WINRT_CALL GetForCurrentView(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowShareUIWithOptions(void* options) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetStaticFragment(void* htmlFormat, void** htmlFragment) noexcept = 0;
    virtual int32_t WINRT_CALL CreateHtmlFormat(void* htmlFragment, void** htmlFormat) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Operation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AcceptedFormatId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ShareTarget(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayIcon(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tag(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Tag(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareProviderFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* title, void* displayIcon, struct struct_Windows_UI_Color backgroundColor, void* handler, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareProviderOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Provider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReportCompleted() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Providers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareTargetInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShareProvider(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IShareUIOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Theme(Windows::ApplicationModel::DataTransfer::ShareUITheme* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Theme(Windows::ApplicationModel::DataTransfer::ShareUITheme value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectionRect(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SelectionRect(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddFile(void* file, void** outToken) noexcept = 0;
    virtual int32_t WINRT_CALL RedeemTokenForFileAsync(void* token, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveFile(void* token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Html(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rtf(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitmap(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StorageItems(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WebLink(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ApplicationLink(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserActivityJsonArray(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ApplicationName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::DataProviderHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* request) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::DataTransfer::ShareProviderHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions
{
    bool IsRoamable() const;
    void IsRoamable(bool value) const;
    bool IsAllowedInHistory() const;
    void IsAllowedInHistory(bool value) const;
    Windows::Foundation::Collections::IVector<hstring> RoamingFormats() const;
    Windows::Foundation::Collections::IVector<hstring> HistoryFormats() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IClipboardContentOptions> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryChangedEventArgs
{
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem
{
    hstring Id() const;
    Windows::Foundation::DateTime Timestamp() const;
    Windows::ApplicationModel::DataTransfer::DataPackageView Content() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItemsResult
{
    Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus Status() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem> Items() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItemsResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics
{
    Windows::ApplicationModel::DataTransfer::DataPackageView GetContent() const;
    void SetContent(Windows::ApplicationModel::DataTransfer::DataPackage const& content) const;
    void Flush() const;
    void Clear() const;
    winrt::event_token ContentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using ContentChanged_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics>::remove_ContentChanged>;
    ContentChanged_revoker ContentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void ContentChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IClipboardStatics> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> GetHistoryItemsAsync() const;
    bool ClearHistory() const;
    bool DeleteItemFromHistory(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item) const;
    Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus SetHistoryItemAsContent(Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item) const;
    bool IsHistoryEnabled() const;
    bool IsRoamingEnabled() const;
    bool SetContentWithOptions(Windows::ApplicationModel::DataTransfer::DataPackage const& content, Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options) const;
    winrt::event_token HistoryChanged(Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler) const;
    using HistoryChanged_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_HistoryChanged>;
    HistoryChanged_revoker HistoryChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler) const;
    void HistoryChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token RoamingEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RoamingEnabledChanged_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_RoamingEnabledChanged>;
    RoamingEnabledChanged_revoker RoamingEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RoamingEnabledChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token HistoryEnabledChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using HistoryEnabledChanged_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IClipboardStatics2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IClipboardStatics2>::remove_HistoryEnabledChanged>;
    HistoryEnabledChanged_revoker HistoryEnabledChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void HistoryEnabledChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IClipboardStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackage
{
    Windows::ApplicationModel::DataTransfer::DataPackageView GetView() const;
    Windows::ApplicationModel::DataTransfer::DataPackagePropertySet Properties() const;
    Windows::ApplicationModel::DataTransfer::DataPackageOperation RequestedOperation() const;
    void RequestedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const;
    winrt::event_token OperationCompleted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const& handler) const;
    using OperationCompleted_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IDataPackage, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IDataPackage>::remove_OperationCompleted>;
    OperationCompleted_revoker OperationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const& handler) const;
    void OperationCompleted(winrt::event_token const& eventCookie) const noexcept;
    winrt::event_token Destroyed(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::Foundation::IInspectable> const& handler) const;
    using Destroyed_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IDataPackage, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IDataPackage>::remove_Destroyed>;
    Destroyed_revoker Destroyed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::Foundation::IInspectable> const& handler) const;
    void Destroyed(winrt::event_token const& eventCookie) const noexcept;
    void SetData(param::hstring const& formatId, Windows::Foundation::IInspectable const& value) const;
    void SetDataProvider(param::hstring const& formatId, Windows::ApplicationModel::DataTransfer::DataProviderHandler const& delayRenderer) const;
    void SetText(param::hstring const& value) const;
    void SetUri(Windows::Foundation::Uri const& value) const;
    void SetHtmlFormat(param::hstring const& value) const;
    Windows::Foundation::Collections::IMap<hstring, Windows::Storage::Streams::RandomAccessStreamReference> ResourceMap() const;
    void SetRtf(param::hstring const& value) const;
    void SetBitmap(Windows::Storage::Streams::RandomAccessStreamReference const& value) const;
    void SetStorageItems(param::iterable<Windows::Storage::IStorageItem> const& value) const;
    void SetStorageItems(param::iterable<Windows::Storage::IStorageItem> const& value, bool readOnly) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackage> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackage2
{
    void SetApplicationLink(Windows::Foundation::Uri const& value) const;
    void SetWebLink(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackage2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackage2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackage3
{
    winrt::event_token ShareCompleted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const& handler) const;
    using ShareCompleted_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IDataPackage3, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IDataPackage3>::remove_ShareCompleted>;
    ShareCompleted_revoker ShareCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataPackage, Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const& handler) const;
    void ShareCompleted(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackage3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet
{
    hstring Title() const;
    void Title(param::hstring const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
    void Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Foundation::Collections::IVector<hstring> FileTypes() const;
    hstring ApplicationName() const;
    void ApplicationName(param::hstring const& value) const;
    Windows::Foundation::Uri ApplicationListingUri() const;
    void ApplicationListingUri(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2
{
    Windows::Foundation::Uri ContentSourceWebLink() const;
    void ContentSourceWebLink(Windows::Foundation::Uri const& value) const;
    Windows::Foundation::Uri ContentSourceApplicationLink() const;
    void ContentSourceApplicationLink(Windows::Foundation::Uri const& value) const;
    hstring PackageFamilyName() const;
    void PackageFamilyName(param::hstring const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Square30x30Logo() const;
    void Square30x30Logo(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::UI::Color LogoBackgroundColor() const;
    void LogoBackgroundColor(Windows::UI::Color const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet3
{
    hstring EnterpriseId() const;
    void EnterpriseId(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet4
{
    hstring ContentSourceUserActivityJson() const;
    void ContentSourceUserActivityJson(param::hstring const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView
{
    hstring Title() const;
    hstring Description() const;
    Windows::Storage::Streams::RandomAccessStreamReference Thumbnail() const;
    Windows::Foundation::Collections::IVectorView<hstring> FileTypes() const;
    hstring ApplicationName() const;
    Windows::Foundation::Uri ApplicationListingUri() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2
{
    hstring PackageFamilyName() const;
    Windows::Foundation::Uri ContentSourceWebLink() const;
    Windows::Foundation::Uri ContentSourceApplicationLink() const;
    Windows::Storage::Streams::IRandomAccessStreamReference Square30x30Logo() const;
    Windows::UI::Color LogoBackgroundColor() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView3
{
    hstring EnterpriseId() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView4
{
    hstring ContentSourceUserActivityJson() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView5
{
    bool IsFromRoamingClipboard() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView5<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackageView
{
    Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView Properties() const;
    Windows::ApplicationModel::DataTransfer::DataPackageOperation RequestedOperation() const;
    void ReportOperationCompleted(Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const;
    Windows::Foundation::Collections::IVectorView<hstring> AvailableFormats() const;
    bool Contains(param::hstring const& formatId) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> GetDataAsync(param::hstring const& formatId) const;
    Windows::Foundation::IAsyncOperation<hstring> GetTextAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetTextAsync(param::hstring const& formatId) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> GetUriAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetHtmlFormatAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::Streams::RandomAccessStreamReference>> GetResourceMapAsync() const;
    Windows::Foundation::IAsyncOperation<hstring> GetRtfAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::RandomAccessStreamReference> GetBitmapAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> GetStorageItemsAsync() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackageView> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackageView2
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> GetApplicationLinkAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Uri> GetWebLinkAsync() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackageView2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackageView2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3
{
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> RequestAccessAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> RequestAccessAsync(param::hstring const& enterpriseId) const;
    Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult UnlockAndAssumeEnterpriseIdentity() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackageView3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataPackageView4
{
    void SetAcceptedFormatId(param::hstring const& formatId) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataPackageView4> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataPackageView4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataProviderDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataProviderDeferral> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataProviderDeferral<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest
{
    hstring FormatId() const;
    Windows::Foundation::DateTime Deadline() const;
    Windows::ApplicationModel::DataTransfer::DataProviderDeferral GetDeferral() const;
    void SetData(Windows::Foundation::IInspectable const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataProviderRequest> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataRequest
{
    Windows::ApplicationModel::DataTransfer::DataPackage Data() const;
    void Data(Windows::ApplicationModel::DataTransfer::DataPackage const& value) const;
    Windows::Foundation::DateTime Deadline() const;
    void FailWithDisplayText(param::hstring const& value) const;
    Windows::ApplicationModel::DataTransfer::DataRequestDeferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataRequest> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataRequestDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataRequestDeferral> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataRequestDeferral<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataRequestedEventArgs
{
    Windows::ApplicationModel::DataTransfer::DataRequest Request() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager
{
    winrt::event_token DataRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const& eventHandler) const;
    using DataRequested_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IDataTransferManager, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IDataTransferManager>::remove_DataRequested>;
    DataRequested_revoker DataRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const& eventHandler) const;
    void DataRequested(winrt::event_token const& eventCookie) const noexcept;
    winrt::event_token TargetApplicationChosen(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const& eventHandler) const;
    using TargetApplicationChosen_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IDataTransferManager, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IDataTransferManager>::remove_TargetApplicationChosen>;
    TargetApplicationChosen_revoker TargetApplicationChosen(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const& eventHandler) const;
    void TargetApplicationChosen(winrt::event_token const& eventCookie) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataTransferManager> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2
{
    winrt::event_token ShareProvidersRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const& handler) const;
    using ShareProvidersRequested_revoker = impl::event_revoker<Windows::ApplicationModel::DataTransfer::IDataTransferManager2, &impl::abi_t<Windows::ApplicationModel::DataTransfer::IDataTransferManager2>::remove_ShareProvidersRequested>;
    ShareProvidersRequested_revoker ShareProvidersRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::DataTransfer::DataTransferManager, Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const& handler) const;
    void ShareProvidersRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataTransferManager2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics
{
    void ShowShareUI() const;
    Windows::ApplicationModel::DataTransfer::DataTransferManager GetForCurrentView() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics2
{
    bool IsSupported() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics3
{
    void ShowShareUI(Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IHtmlFormatHelperStatics
{
    hstring GetStaticFragment(param::hstring const& htmlFormat) const;
    hstring CreateHtmlFormat(param::hstring const& htmlFragment) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IHtmlFormatHelperStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation Operation() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs2
{
    hstring AcceptedFormatId() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareCompletedEventArgs
{
    Windows::ApplicationModel::DataTransfer::ShareTargetInfo ShareTarget() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareCompletedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareProvider
{
    hstring Title() const;
    Windows::Storage::Streams::RandomAccessStreamReference DisplayIcon() const;
    Windows::UI::Color BackgroundColor() const;
    Windows::Foundation::IInspectable Tag() const;
    void Tag(Windows::Foundation::IInspectable const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareProvider> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareProviderFactory
{
    Windows::ApplicationModel::DataTransfer::ShareProvider Create(param::hstring const& title, Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, Windows::UI::Color const& backgroundColor, Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareProviderFactory> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareProviderFactory<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation
{
    Windows::ApplicationModel::DataTransfer::DataPackageView Data() const;
    Windows::ApplicationModel::DataTransfer::ShareProvider Provider() const;
    void ReportCompleted() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareProviderOperation> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::DataTransfer::ShareProvider> Providers() const;
    Windows::ApplicationModel::DataTransfer::DataPackageView Data() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareTargetInfo
{
    hstring AppUserModelId() const;
    Windows::ApplicationModel::DataTransfer::ShareProvider ShareProvider() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareTargetInfo> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareTargetInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions
{
    Windows::ApplicationModel::DataTransfer::ShareUITheme Theme() const;
    void Theme(Windows::ApplicationModel::DataTransfer::ShareUITheme const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::Rect> SelectionRect() const;
    void SelectionRect(optional<Windows::Foundation::Rect> const& value) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IShareUIOptions> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics
{
    hstring AddFile(Windows::Storage::IStorageFile const& file) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> RedeemTokenForFileAsync(param::hstring const& token) const;
    void RemoveFile(param::hstring const& token) const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics
{
    hstring Text() const;
    hstring Uri() const;
    hstring Html() const;
    hstring Rtf() const;
    hstring Bitmap() const;
    hstring StorageItems() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics2
{
    hstring WebLink() const;
    hstring ApplicationLink() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics3
{
    hstring UserActivityJsonArray() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_DataTransfer_ITargetApplicationChosenEventArgs
{
    hstring ApplicationName() const;
};
template <> struct consume<Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ITargetApplicationChosenEventArgs<D>; };

}
