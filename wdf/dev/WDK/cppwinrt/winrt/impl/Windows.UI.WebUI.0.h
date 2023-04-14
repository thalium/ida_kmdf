// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

struct IEnteredBackgroundEventArgs;
struct ILeavingBackgroundEventArgs;
struct ISuspendingEventArgs;
struct SuspendingDeferral;
struct SuspendingOperation;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation {

enum class ActivationKind;
enum class ApplicationExecutionState;
struct CommandLineActivationOperation;
struct IActivatedEventArgs;
struct IBackgroundActivatedEventArgs;
struct SplashScreen;
struct TileActivatedInfo;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider {

struct AddAppointmentOperation;
struct RemoveAppointmentOperation;
struct ReplaceAppointmentOperation;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Background {

struct BackgroundTaskCanceledEventHandler;
struct BackgroundTaskDeferral;
struct BackgroundTaskRegistration;
struct IBackgroundTaskInstance;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls {

struct LockScreenCallUI;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts {

struct Contact;
struct ContactAddress;
struct ContactPanel;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::Provider {

struct ContactPickerUI;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core {

enum class AppRestartFailureReason;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer {

struct DataPackage;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget {

struct ShareOperation;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search {

struct SearchPaneQueryLinguisticDetails;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::Provider {

struct IUserDataAccountProviderOperation;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet {

enum class WalletActionKind;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

struct DeviceInformation;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Printers::Extensions {

struct Print3DWorkflow;
struct PrintTaskConfiguration;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;
struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct ValueSet;

}

WINRT_EXPORT namespace winrt::Windows::Media::SpeechRecognition {

struct SpeechRecognitionResult;

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web {

struct WebAuthenticationResult;

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Provider {

struct IWebAccountProviderOperation;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageItem;
struct StorageFile;
struct StorageFolder;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Pickers::Provider {

struct FileOpenPickerUI;
struct FileSavePickerUI;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Provider {

struct CachedFileUpdaterUI;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Search {

struct StorageFileQueryResult;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct ProtocolForResultsOperation;
struct User;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::Web {

struct IUriToStreamResolver;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

struct HttpRequestMessage;

}

WINRT_EXPORT namespace winrt::Windows::Web::UI {

struct IWebViewControl;
struct WebViewControlContentLoadingEventArgs;
struct WebViewControlDOMContentLoadedEventArgs;
struct WebViewControlDeferredPermissionRequest;
struct WebViewControlLongRunningScriptDetectedEventArgs;
struct WebViewControlNavigationCompletedEventArgs;
struct WebViewControlNavigationStartingEventArgs;
struct WebViewControlNewWindowRequestedEventArgs;
struct WebViewControlPermissionRequestedEventArgs;
struct WebViewControlScriptNotifyEventArgs;
struct WebViewControlSettings;
struct WebViewControlUnsupportedUriSchemeIdentifiedEventArgs;
struct WebViewControlUnviewableContentIdentifiedEventArgs;
struct WebViewControlWebResourceRequestedEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

struct IEnteredBackgroundEventArgs;
struct ILeavingBackgroundEventArgs;
struct ISuspendingDeferral;
struct ISuspendingEventArgs;
struct ISuspendingOperation;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation {

struct IActivatedEventArgs;
struct IAppointmentsProviderAddAppointmentActivatedEventArgs;
struct IAppointmentsProviderRemoveAppointmentActivatedEventArgs;
struct IAppointmentsProviderReplaceAppointmentActivatedEventArgs;
struct IAppointmentsProviderShowAppointmentDetailsActivatedEventArgs;
struct IAppointmentsProviderShowTimeFrameActivatedEventArgs;
struct IBackgroundActivatedEventArgs;
struct IBarcodeScannerPreviewActivatedEventArgs;
struct ICachedFileUpdaterActivatedEventArgs;
struct ICameraSettingsActivatedEventArgs;
struct ICommandLineActivatedEventArgs;
struct IContactCallActivatedEventArgs;
struct IContactMapActivatedEventArgs;
struct IContactMessageActivatedEventArgs;
struct IContactPanelActivatedEventArgs;
struct IContactPickerActivatedEventArgs;
struct IContactPostActivatedEventArgs;
struct IContactVideoCallActivatedEventArgs;
struct IDeviceActivatedEventArgs;
struct IDevicePairingActivatedEventArgs;
struct IDialReceiverActivatedEventArgs;
struct IFileActivatedEventArgs;
struct IFileOpenPickerActivatedEventArgs;
struct IFileOpenPickerContinuationEventArgs;
struct IFileSavePickerActivatedEventArgs;
struct IFileSavePickerContinuationEventArgs;
struct IFolderPickerContinuationEventArgs;
struct ILaunchActivatedEventArgs;
struct ILockScreenActivatedEventArgs;
struct ILockScreenCallActivatedEventArgs;
struct IPrint3DWorkflowActivatedEventArgs;
struct IPrintTaskSettingsActivatedEventArgs;
struct IProtocolActivatedEventArgs;
struct IProtocolForResultsActivatedEventArgs;
struct IRestrictedLaunchActivatedEventArgs;
struct ISearchActivatedEventArgs;
struct IShareTargetActivatedEventArgs;
struct IStartupTaskActivatedEventArgs;
struct IToastNotificationActivatedEventArgs;
struct IUserDataAccountProviderActivatedEventArgs;
struct IVoiceCommandActivatedEventArgs;
struct IWalletActionActivatedEventArgs;
struct IWebAccountProviderActivatedEventArgs;
struct IWebAuthenticationBrokerContinuationEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::UI::WebUI {

enum class PrintContent : int32_t
{
    AllPages = 0,
    CurrentPage = 1,
    CustomPageRange = 2,
    CurrentSelection = 3,
};

struct IActivatedDeferral;
struct IActivatedEventArgsDeferral;
struct IActivatedOperation;
struct IHtmlPrintDocumentSource;
struct INewWebUIViewCreatedEventArgs;
struct IWebUIActivationStatics;
struct IWebUIActivationStatics2;
struct IWebUIActivationStatics3;
struct IWebUIActivationStatics4;
struct IWebUIBackgroundTaskInstance;
struct IWebUIBackgroundTaskInstanceStatics;
struct IWebUINavigatedDeferral;
struct IWebUINavigatedEventArgs;
struct IWebUINavigatedOperation;
struct IWebUIView;
struct IWebUIViewStatics;
struct ActivatedDeferral;
struct ActivatedOperation;
struct BackgroundActivatedEventArgs;
struct EnteredBackgroundEventArgs;
struct HtmlPrintDocumentSource;
struct LeavingBackgroundEventArgs;
struct NewWebUIViewCreatedEventArgs;
struct SuspendingDeferral;
struct SuspendingEventArgs;
struct SuspendingOperation;
struct WebUIApplication;
struct WebUIAppointmentsProviderAddAppointmentActivatedEventArgs;
struct WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs;
struct WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs;
struct WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs;
struct WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs;
struct WebUIBackgroundTaskInstance;
struct WebUIBackgroundTaskInstanceRuntimeClass;
struct WebUIBarcodeScannerPreviewActivatedEventArgs;
struct WebUICachedFileUpdaterActivatedEventArgs;
struct WebUICameraSettingsActivatedEventArgs;
struct WebUICommandLineActivatedEventArgs;
struct WebUIContactCallActivatedEventArgs;
struct WebUIContactMapActivatedEventArgs;
struct WebUIContactMessageActivatedEventArgs;
struct WebUIContactPanelActivatedEventArgs;
struct WebUIContactPickerActivatedEventArgs;
struct WebUIContactPostActivatedEventArgs;
struct WebUIContactVideoCallActivatedEventArgs;
struct WebUIDeviceActivatedEventArgs;
struct WebUIDevicePairingActivatedEventArgs;
struct WebUIDialReceiverActivatedEventArgs;
struct WebUIFileActivatedEventArgs;
struct WebUIFileOpenPickerActivatedEventArgs;
struct WebUIFileOpenPickerContinuationEventArgs;
struct WebUIFileSavePickerActivatedEventArgs;
struct WebUIFileSavePickerContinuationEventArgs;
struct WebUIFolderPickerContinuationEventArgs;
struct WebUILaunchActivatedEventArgs;
struct WebUILockScreenActivatedEventArgs;
struct WebUILockScreenCallActivatedEventArgs;
struct WebUILockScreenComponentActivatedEventArgs;
struct WebUINavigatedDeferral;
struct WebUINavigatedEventArgs;
struct WebUINavigatedOperation;
struct WebUIPrint3DWorkflowActivatedEventArgs;
struct WebUIPrintTaskSettingsActivatedEventArgs;
struct WebUIPrintWorkflowForegroundTaskActivatedEventArgs;
struct WebUIProtocolActivatedEventArgs;
struct WebUIProtocolForResultsActivatedEventArgs;
struct WebUIRestrictedLaunchActivatedEventArgs;
struct WebUISearchActivatedEventArgs;
struct WebUIShareTargetActivatedEventArgs;
struct WebUIStartupTaskActivatedEventArgs;
struct WebUIToastNotificationActivatedEventArgs;
struct WebUIUserDataAccountProviderActivatedEventArgs;
struct WebUIView;
struct WebUIVoiceCommandActivatedEventArgs;
struct WebUIWalletActionActivatedEventArgs;
struct WebUIWebAccountProviderActivatedEventArgs;
struct WebUIWebAuthenticationBrokerContinuationEventArgs;
struct ActivatedEventHandler;
struct BackgroundActivatedEventHandler;
struct EnteredBackgroundEventHandler;
struct LeavingBackgroundEventHandler;
struct NavigatedEventHandler;
struct ResumingEventHandler;
struct SuspendingEventHandler;

}

namespace winrt::impl {

template <> struct category<Windows::UI::WebUI::IActivatedDeferral>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IActivatedEventArgsDeferral>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IActivatedOperation>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IHtmlPrintDocumentSource>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::INewWebUIViewCreatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIActivationStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIActivationStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIActivationStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIActivationStatics4>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIBackgroundTaskInstance>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUINavigatedDeferral>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUINavigatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUINavigatedOperation>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIView>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::IWebUIViewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::WebUI::ActivatedDeferral>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::ActivatedOperation>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::BackgroundActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::EnteredBackgroundEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::HtmlPrintDocumentSource>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::LeavingBackgroundEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::SuspendingDeferral>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::SuspendingEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::SuspendingOperation>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIApplication>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIAppointmentsProviderAddAppointmentActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIBackgroundTaskInstance>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIBackgroundTaskInstanceRuntimeClass>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIBarcodeScannerPreviewActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUICachedFileUpdaterActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUICameraSettingsActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUICommandLineActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactCallActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactMapActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactMessageActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactPanelActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactPickerActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactPostActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIContactVideoCallActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIDeviceActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIDevicePairingActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIDialReceiverActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIFileActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIFileOpenPickerActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIFileOpenPickerContinuationEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIFileSavePickerActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIFileSavePickerContinuationEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIFolderPickerContinuationEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUILaunchActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUILockScreenActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUILockScreenCallActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUILockScreenComponentActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUINavigatedDeferral>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUINavigatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUINavigatedOperation>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIPrint3DWorkflowActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIPrintTaskSettingsActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIPrintWorkflowForegroundTaskActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIProtocolActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIProtocolForResultsActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIRestrictedLaunchActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUISearchActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIShareTargetActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIStartupTaskActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIToastNotificationActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIUserDataAccountProviderActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIView>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIVoiceCommandActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIWalletActionActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIWebAccountProviderActivatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::WebUIWebAuthenticationBrokerContinuationEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::WebUI::PrintContent>{ using type = enum_category; };
template <> struct category<Windows::UI::WebUI::ActivatedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::WebUI::BackgroundActivatedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::WebUI::EnteredBackgroundEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::WebUI::LeavingBackgroundEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::WebUI::NavigatedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::WebUI::ResumingEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::WebUI::SuspendingEventHandler>{ using type = delegate_category; };
template <> struct name<Windows::UI::WebUI::IActivatedDeferral>{ static constexpr auto & value{ L"Windows.UI.WebUI.IActivatedDeferral" }; };
template <> struct name<Windows::UI::WebUI::IActivatedEventArgsDeferral>{ static constexpr auto & value{ L"Windows.UI.WebUI.IActivatedEventArgsDeferral" }; };
template <> struct name<Windows::UI::WebUI::IActivatedOperation>{ static constexpr auto & value{ L"Windows.UI.WebUI.IActivatedOperation" }; };
template <> struct name<Windows::UI::WebUI::IHtmlPrintDocumentSource>{ static constexpr auto & value{ L"Windows.UI.WebUI.IHtmlPrintDocumentSource" }; };
template <> struct name<Windows::UI::WebUI::INewWebUIViewCreatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.INewWebUIViewCreatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::IWebUIActivationStatics>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIActivationStatics" }; };
template <> struct name<Windows::UI::WebUI::IWebUIActivationStatics2>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIActivationStatics2" }; };
template <> struct name<Windows::UI::WebUI::IWebUIActivationStatics3>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIActivationStatics3" }; };
template <> struct name<Windows::UI::WebUI::IWebUIActivationStatics4>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIActivationStatics4" }; };
template <> struct name<Windows::UI::WebUI::IWebUIBackgroundTaskInstance>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIBackgroundTaskInstance" }; };
template <> struct name<Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIBackgroundTaskInstanceStatics" }; };
template <> struct name<Windows::UI::WebUI::IWebUINavigatedDeferral>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUINavigatedDeferral" }; };
template <> struct name<Windows::UI::WebUI::IWebUINavigatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUINavigatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::IWebUINavigatedOperation>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUINavigatedOperation" }; };
template <> struct name<Windows::UI::WebUI::IWebUIView>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIView" }; };
template <> struct name<Windows::UI::WebUI::IWebUIViewStatics>{ static constexpr auto & value{ L"Windows.UI.WebUI.IWebUIViewStatics" }; };
template <> struct name<Windows::UI::WebUI::ActivatedDeferral>{ static constexpr auto & value{ L"Windows.UI.WebUI.ActivatedDeferral" }; };
template <> struct name<Windows::UI::WebUI::ActivatedOperation>{ static constexpr auto & value{ L"Windows.UI.WebUI.ActivatedOperation" }; };
template <> struct name<Windows::UI::WebUI::BackgroundActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.BackgroundActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::EnteredBackgroundEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.EnteredBackgroundEventArgs" }; };
template <> struct name<Windows::UI::WebUI::HtmlPrintDocumentSource>{ static constexpr auto & value{ L"Windows.UI.WebUI.HtmlPrintDocumentSource" }; };
template <> struct name<Windows::UI::WebUI::LeavingBackgroundEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.LeavingBackgroundEventArgs" }; };
template <> struct name<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.NewWebUIViewCreatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::SuspendingDeferral>{ static constexpr auto & value{ L"Windows.UI.WebUI.SuspendingDeferral" }; };
template <> struct name<Windows::UI::WebUI::SuspendingEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.SuspendingEventArgs" }; };
template <> struct name<Windows::UI::WebUI::SuspendingOperation>{ static constexpr auto & value{ L"Windows.UI.WebUI.SuspendingOperation" }; };
template <> struct name<Windows::UI::WebUI::WebUIApplication>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIApplication" }; };
template <> struct name<Windows::UI::WebUI::WebUIAppointmentsProviderAddAppointmentActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIAppointmentsProviderAddAppointmentActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIBackgroundTaskInstance>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIBackgroundTaskInstance" }; };
template <> struct name<Windows::UI::WebUI::WebUIBackgroundTaskInstanceRuntimeClass>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIBackgroundTaskInstanceRuntimeClass" }; };
template <> struct name<Windows::UI::WebUI::WebUIBarcodeScannerPreviewActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIBarcodeScannerPreviewActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUICachedFileUpdaterActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUICachedFileUpdaterActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUICameraSettingsActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUICameraSettingsActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUICommandLineActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUICommandLineActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactCallActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactCallActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactMapActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactMapActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactMessageActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactMessageActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactPanelActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactPanelActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactPickerActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactPickerActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactPostActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactPostActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIContactVideoCallActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIContactVideoCallActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIDeviceActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIDeviceActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIDevicePairingActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIDevicePairingActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIDialReceiverActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIDialReceiverActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIFileActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIFileActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIFileOpenPickerActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIFileOpenPickerActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIFileOpenPickerContinuationEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIFileOpenPickerContinuationEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIFileSavePickerActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIFileSavePickerActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIFileSavePickerContinuationEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIFileSavePickerContinuationEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIFolderPickerContinuationEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIFolderPickerContinuationEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUILaunchActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUILaunchActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUILockScreenActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUILockScreenActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUILockScreenCallActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUILockScreenCallActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUILockScreenComponentActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUILockScreenComponentActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUINavigatedDeferral>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUINavigatedDeferral" }; };
template <> struct name<Windows::UI::WebUI::WebUINavigatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUINavigatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUINavigatedOperation>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUINavigatedOperation" }; };
template <> struct name<Windows::UI::WebUI::WebUIPrint3DWorkflowActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIPrint3DWorkflowActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIPrintTaskSettingsActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIPrintTaskSettingsActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIPrintWorkflowForegroundTaskActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIPrintWorkflowForegroundTaskActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIProtocolActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIProtocolActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIProtocolForResultsActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIProtocolForResultsActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIRestrictedLaunchActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIRestrictedLaunchActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUISearchActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUISearchActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIShareTargetActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIShareTargetActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIStartupTaskActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIStartupTaskActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIToastNotificationActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIToastNotificationActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIUserDataAccountProviderActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIUserDataAccountProviderActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIView>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIView" }; };
template <> struct name<Windows::UI::WebUI::WebUIVoiceCommandActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIVoiceCommandActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIWalletActionActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIWalletActionActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIWebAccountProviderActivatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIWebAccountProviderActivatedEventArgs" }; };
template <> struct name<Windows::UI::WebUI::WebUIWebAuthenticationBrokerContinuationEventArgs>{ static constexpr auto & value{ L"Windows.UI.WebUI.WebUIWebAuthenticationBrokerContinuationEventArgs" }; };
template <> struct name<Windows::UI::WebUI::PrintContent>{ static constexpr auto & value{ L"Windows.UI.WebUI.PrintContent" }; };
template <> struct name<Windows::UI::WebUI::ActivatedEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.ActivatedEventHandler" }; };
template <> struct name<Windows::UI::WebUI::BackgroundActivatedEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.BackgroundActivatedEventHandler" }; };
template <> struct name<Windows::UI::WebUI::EnteredBackgroundEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.EnteredBackgroundEventHandler" }; };
template <> struct name<Windows::UI::WebUI::LeavingBackgroundEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.LeavingBackgroundEventHandler" }; };
template <> struct name<Windows::UI::WebUI::NavigatedEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.NavigatedEventHandler" }; };
template <> struct name<Windows::UI::WebUI::ResumingEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.ResumingEventHandler" }; };
template <> struct name<Windows::UI::WebUI::SuspendingEventHandler>{ static constexpr auto & value{ L"Windows.UI.WebUI.SuspendingEventHandler" }; };
template <> struct guid_storage<Windows::UI::WebUI::IActivatedDeferral>{ static constexpr guid value{ 0xC3BD1978,0xA431,0x49D8,{ 0xA7,0x6A,0x39,0x5A,0x4E,0x03,0xDC,0xF3 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IActivatedEventArgsDeferral>{ static constexpr guid value{ 0xCA6D5F74,0x63C2,0x44A6,{ 0xB9,0x7B,0xD9,0xA0,0x3C,0x20,0xBC,0x9B } }; };
template <> struct guid_storage<Windows::UI::WebUI::IActivatedOperation>{ static constexpr guid value{ 0xB6A0B4BC,0xC6CA,0x42FD,{ 0x98,0x18,0x71,0x90,0x4E,0x45,0xFE,0xD7 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IHtmlPrintDocumentSource>{ static constexpr guid value{ 0xCEA6469A,0x0E05,0x467A,{ 0xAB,0xC9,0x36,0xEC,0x1D,0x4C,0xDC,0xB6 } }; };
template <> struct guid_storage<Windows::UI::WebUI::INewWebUIViewCreatedEventArgs>{ static constexpr guid value{ 0xE8E1B216,0xBE2B,0x4C9E,{ 0x85,0xE7,0x08,0x31,0x43,0xEC,0x4B,0xE7 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIActivationStatics>{ static constexpr guid value{ 0x351B86BD,0x43B3,0x482B,{ 0x85,0xDB,0x35,0xD8,0x7B,0x51,0x7A,0xD9 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIActivationStatics2>{ static constexpr guid value{ 0xC8E88696,0x4D78,0x4AA4,{ 0x8F,0x06,0x2A,0x9E,0xAD,0xC6,0xC4,0x0A } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIActivationStatics3>{ static constexpr guid value{ 0x91ABB686,0x1AF5,0x4445,{ 0xB4,0x9F,0x94,0x59,0xF4,0x0F,0xC8,0xDE } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIActivationStatics4>{ static constexpr guid value{ 0x5E391429,0x183F,0x478D,{ 0x8A,0x25,0x67,0xF8,0x0D,0x03,0x93,0x5B } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIBackgroundTaskInstance>{ static constexpr guid value{ 0x23F12C25,0xE2F7,0x4741,{ 0xBC,0x9C,0x39,0x45,0x95,0xDE,0x24,0xDC } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics>{ static constexpr guid value{ 0x9C7A5291,0x19AE,0x4CA3,{ 0xB9,0x4B,0xFE,0x4E,0xC7,0x44,0xA7,0x40 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUINavigatedDeferral>{ static constexpr guid value{ 0xD804204D,0x831F,0x46E2,{ 0xB4,0x32,0x3A,0xFC,0xE2,0x11,0xF9,0x62 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUINavigatedEventArgs>{ static constexpr guid value{ 0xA75841B8,0x2499,0x4030,{ 0xA6,0x9D,0x15,0xD2,0xD9,0xCF,0xE5,0x24 } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUINavigatedOperation>{ static constexpr guid value{ 0x7A965F08,0x8182,0x4A89,{ 0xAB,0x67,0x84,0x92,0xE8,0x75,0x0D,0x4B } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIView>{ static constexpr guid value{ 0x6783F64F,0x52DA,0x4FD7,{ 0xBE,0x69,0x8E,0xF6,0x28,0x4B,0x42,0x3C } }; };
template <> struct guid_storage<Windows::UI::WebUI::IWebUIViewStatics>{ static constexpr guid value{ 0xB591E668,0x8E59,0x44F9,{ 0x88,0x03,0x1B,0x24,0xC9,0x14,0x9D,0x30 } }; };
template <> struct guid_storage<Windows::UI::WebUI::ActivatedEventHandler>{ static constexpr guid value{ 0x50F1E730,0xC5D1,0x4B6B,{ 0x9A,0xDB,0x8A,0x11,0x75,0x6B,0xE2,0x9C } }; };
template <> struct guid_storage<Windows::UI::WebUI::BackgroundActivatedEventHandler>{ static constexpr guid value{ 0xEDB19FBB,0x0761,0x47CC,{ 0x9A,0x77,0x24,0xD7,0x07,0x29,0x65,0xCA } }; };
template <> struct guid_storage<Windows::UI::WebUI::EnteredBackgroundEventHandler>{ static constexpr guid value{ 0x2B09A173,0xB68E,0x4DEF,{ 0x88,0xC1,0x8D,0xE8,0x4E,0x5A,0xAB,0x2F } }; };
template <> struct guid_storage<Windows::UI::WebUI::LeavingBackgroundEventHandler>{ static constexpr guid value{ 0x00B4CCD9,0x7A9C,0x4B6B,{ 0x9A,0xC4,0x13,0x47,0x4F,0x26,0x8B,0xC4 } }; };
template <> struct guid_storage<Windows::UI::WebUI::NavigatedEventHandler>{ static constexpr guid value{ 0x7AF46FE6,0x40CA,0x4E49,{ 0xA7,0xD6,0xDB,0xDB,0x33,0x0C,0xD1,0xA3 } }; };
template <> struct guid_storage<Windows::UI::WebUI::ResumingEventHandler>{ static constexpr guid value{ 0x26599BA9,0xA22D,0x4806,{ 0xA7,0x28,0xAC,0xAD,0xC1,0xD0,0x75,0xFA } }; };
template <> struct guid_storage<Windows::UI::WebUI::SuspendingEventHandler>{ static constexpr guid value{ 0x509C429C,0x78E2,0x4883,{ 0xAB,0xC8,0x89,0x60,0xDC,0xDE,0x1B,0x5C } }; };
template <> struct default_interface<Windows::UI::WebUI::ActivatedDeferral>{ using type = Windows::UI::WebUI::IActivatedDeferral; };
template <> struct default_interface<Windows::UI::WebUI::ActivatedOperation>{ using type = Windows::UI::WebUI::IActivatedOperation; };
template <> struct default_interface<Windows::UI::WebUI::BackgroundActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::EnteredBackgroundEventArgs>{ using type = Windows::ApplicationModel::IEnteredBackgroundEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::HtmlPrintDocumentSource>{ using type = Windows::UI::WebUI::IHtmlPrintDocumentSource; };
template <> struct default_interface<Windows::UI::WebUI::LeavingBackgroundEventArgs>{ using type = Windows::ApplicationModel::ILeavingBackgroundEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs>{ using type = Windows::UI::WebUI::INewWebUIViewCreatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::SuspendingDeferral>{ using type = Windows::ApplicationModel::ISuspendingDeferral; };
template <> struct default_interface<Windows::UI::WebUI::SuspendingEventArgs>{ using type = Windows::ApplicationModel::ISuspendingEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::SuspendingOperation>{ using type = Windows::ApplicationModel::ISuspendingOperation; };
template <> struct default_interface<Windows::UI::WebUI::WebUIAppointmentsProviderAddAppointmentActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IAppointmentsProviderAddAppointmentActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IAppointmentsProviderRemoveAppointmentActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IAppointmentsProviderReplaceAppointmentActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IAppointmentsProviderShowAppointmentDetailsActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IAppointmentsProviderShowTimeFrameActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIBackgroundTaskInstanceRuntimeClass>{ using type = Windows::UI::WebUI::IWebUIBackgroundTaskInstance; };
template <> struct default_interface<Windows::UI::WebUI::WebUIBarcodeScannerPreviewActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IBarcodeScannerPreviewActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUICachedFileUpdaterActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ICachedFileUpdaterActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUICameraSettingsActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ICameraSettingsActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUICommandLineActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ICommandLineActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactCallActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactCallActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactMapActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactMapActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactMessageActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactMessageActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactPanelActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactPanelActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactPickerActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactPickerActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactPostActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactPostActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIContactVideoCallActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IContactVideoCallActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIDeviceActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IDeviceActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIDevicePairingActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IDevicePairingActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIDialReceiverActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IDialReceiverActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIFileActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IFileActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIFileOpenPickerActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IFileOpenPickerActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIFileOpenPickerContinuationEventArgs>{ using type = Windows::ApplicationModel::Activation::IFileOpenPickerContinuationEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIFileSavePickerActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IFileSavePickerActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIFileSavePickerContinuationEventArgs>{ using type = Windows::ApplicationModel::Activation::IFileSavePickerContinuationEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIFolderPickerContinuationEventArgs>{ using type = Windows::ApplicationModel::Activation::IFolderPickerContinuationEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUILaunchActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ILaunchActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUILockScreenActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ILockScreenActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUILockScreenCallActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ILockScreenCallActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUILockScreenComponentActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUINavigatedDeferral>{ using type = Windows::UI::WebUI::IWebUINavigatedDeferral; };
template <> struct default_interface<Windows::UI::WebUI::WebUINavigatedEventArgs>{ using type = Windows::UI::WebUI::IWebUINavigatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUINavigatedOperation>{ using type = Windows::UI::WebUI::IWebUINavigatedOperation; };
template <> struct default_interface<Windows::UI::WebUI::WebUIPrint3DWorkflowActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IPrint3DWorkflowActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIPrintTaskSettingsActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IPrintTaskSettingsActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIPrintWorkflowForegroundTaskActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIProtocolActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IProtocolActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIProtocolForResultsActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IProtocolForResultsActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIRestrictedLaunchActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IRestrictedLaunchActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUISearchActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::ISearchActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIShareTargetActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IShareTargetActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIStartupTaskActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IStartupTaskActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIToastNotificationActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IToastNotificationActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIUserDataAccountProviderActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IUserDataAccountProviderActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIView>{ using type = Windows::UI::WebUI::IWebUIView; };
template <> struct default_interface<Windows::UI::WebUI::WebUIVoiceCommandActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IVoiceCommandActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIWalletActionActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IWalletActionActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIWebAccountProviderActivatedEventArgs>{ using type = Windows::ApplicationModel::Activation::IWebAccountProviderActivatedEventArgs; };
template <> struct default_interface<Windows::UI::WebUI::WebUIWebAuthenticationBrokerContinuationEventArgs>{ using type = Windows::ApplicationModel::Activation::IWebAuthenticationBrokerContinuationEventArgs; };

template <> struct abi<Windows::UI::WebUI::IActivatedDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IActivatedEventArgsDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivatedOperation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IActivatedOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** deferral) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IHtmlPrintDocumentSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Content(Windows::UI::WebUI::PrintContent* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Content(Windows::UI::WebUI::PrintContent value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LeftMargin(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LeftMargin(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TopMargin(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TopMargin(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RightMargin(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RightMargin(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BottomMargin(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BottomMargin(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EnableHeaderFooter(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EnableHeaderFooter(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShrinkToFit(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ShrinkToFit(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PercentScale(float* pScalePercent) noexcept = 0;
    virtual int32_t WINRT_CALL put_PercentScale(float scalePercent) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageRange(void** pstrPageRange) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetPageRange(void* strPageRange, bool* pfSuccess) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::INewWebUIViewCreatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WebUIView(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ActivatedEventArgs(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasPendingNavigate(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIActivationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Activated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Suspending(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Suspending(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Resuming(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Resuming(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Navigated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Navigated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIActivationStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_LeavingBackground(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LeavingBackground(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnteredBackground(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnteredBackground(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL EnablePrelaunch(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIActivationStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestRestartAsync(void* launchArguments, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestRestartForUserAsync(void* user, void* launchArguments, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIActivationStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_NewWebUIViewCreated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NewWebUIViewCreated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BackgroundActivated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BackgroundActivated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIBackgroundTaskInstance>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Succeeded(bool* succeeded) noexcept = 0;
    virtual int32_t WINRT_CALL put_Succeeded(bool succeeded) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** backgroundTaskInstance) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUINavigatedDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUINavigatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NavigatedOperation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUINavigatedOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** deferral) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ApplicationViewId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Activated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_IgnoreApplicationContentUriRulesNavigationRestrictions(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IgnoreApplicationContentUriRulesNavigationRestrictions(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::IWebUIViewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithUriAsync(void* uri, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::ActivatedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* eventArgs) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::BackgroundActivatedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* eventArgs) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::EnteredBackgroundEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::LeavingBackgroundEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::NavigatedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::ResumingEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender) noexcept = 0;
};};

template <> struct abi<Windows::UI::WebUI::SuspendingEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_WebUI_IActivatedDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::UI::WebUI::IActivatedDeferral> { template <typename D> using type = consume_Windows_UI_WebUI_IActivatedDeferral<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IActivatedEventArgsDeferral
{
    Windows::UI::WebUI::ActivatedOperation ActivatedOperation() const;
};
template <> struct consume<Windows::UI::WebUI::IActivatedEventArgsDeferral> { template <typename D> using type = consume_Windows_UI_WebUI_IActivatedEventArgsDeferral<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IActivatedOperation
{
    Windows::UI::WebUI::ActivatedDeferral GetDeferral() const;
};
template <> struct consume<Windows::UI::WebUI::IActivatedOperation> { template <typename D> using type = consume_Windows_UI_WebUI_IActivatedOperation<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IHtmlPrintDocumentSource
{
    Windows::UI::WebUI::PrintContent Content() const;
    void Content(Windows::UI::WebUI::PrintContent const& value) const;
    float LeftMargin() const;
    void LeftMargin(float value) const;
    float TopMargin() const;
    void TopMargin(float value) const;
    float RightMargin() const;
    void RightMargin(float value) const;
    float BottomMargin() const;
    void BottomMargin(float value) const;
    bool EnableHeaderFooter() const;
    void EnableHeaderFooter(bool value) const;
    bool ShrinkToFit() const;
    void ShrinkToFit(bool value) const;
    float PercentScale() const;
    void PercentScale(float scalePercent) const;
    hstring PageRange() const;
    bool TrySetPageRange(param::hstring const& strPageRange) const;
};
template <> struct consume<Windows::UI::WebUI::IHtmlPrintDocumentSource> { template <typename D> using type = consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_INewWebUIViewCreatedEventArgs
{
    Windows::UI::WebUI::WebUIView WebUIView() const;
    Windows::ApplicationModel::Activation::IActivatedEventArgs ActivatedEventArgs() const;
    bool HasPendingNavigate() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::UI::WebUI::INewWebUIViewCreatedEventArgs> { template <typename D> using type = consume_Windows_UI_WebUI_INewWebUIViewCreatedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIActivationStatics
{
    winrt::event_token Activated(Windows::UI::WebUI::ActivatedEventHandler const& handler) const;
    using Activated_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics>::remove_Activated>;
    Activated_revoker Activated(auto_revoke_t, Windows::UI::WebUI::ActivatedEventHandler const& handler) const;
    void Activated(winrt::event_token const& token) const noexcept;
    winrt::event_token Suspending(Windows::UI::WebUI::SuspendingEventHandler const& handler) const;
    using Suspending_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics>::remove_Suspending>;
    Suspending_revoker Suspending(auto_revoke_t, Windows::UI::WebUI::SuspendingEventHandler const& handler) const;
    void Suspending(winrt::event_token const& token) const noexcept;
    winrt::event_token Resuming(Windows::UI::WebUI::ResumingEventHandler const& handler) const;
    using Resuming_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics>::remove_Resuming>;
    Resuming_revoker Resuming(auto_revoke_t, Windows::UI::WebUI::ResumingEventHandler const& handler) const;
    void Resuming(winrt::event_token const& token) const noexcept;
    winrt::event_token Navigated(Windows::UI::WebUI::NavigatedEventHandler const& handler) const;
    using Navigated_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics>::remove_Navigated>;
    Navigated_revoker Navigated(auto_revoke_t, Windows::UI::WebUI::NavigatedEventHandler const& handler) const;
    void Navigated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::WebUI::IWebUIActivationStatics> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIActivationStatics<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIActivationStatics2
{
    winrt::event_token LeavingBackground(Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler) const;
    using LeavingBackground_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics2, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics2>::remove_LeavingBackground>;
    LeavingBackground_revoker LeavingBackground(auto_revoke_t, Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler) const;
    void LeavingBackground(winrt::event_token const& token) const noexcept;
    winrt::event_token EnteredBackground(Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler) const;
    using EnteredBackground_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics2, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics2>::remove_EnteredBackground>;
    EnteredBackground_revoker EnteredBackground(auto_revoke_t, Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler) const;
    void EnteredBackground(winrt::event_token const& token) const noexcept;
    void EnablePrelaunch(bool value) const;
};
template <> struct consume<Windows::UI::WebUI::IWebUIActivationStatics2> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIActivationStatics3
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> RequestRestartAsync(param::hstring const& launchArguments) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> RequestRestartForUserAsync(Windows::System::User const& user, param::hstring const& launchArguments) const;
};
template <> struct consume<Windows::UI::WebUI::IWebUIActivationStatics3> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIActivationStatics3<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIActivationStatics4
{
    winrt::event_token NewWebUIViewCreated(Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler) const;
    using NewWebUIViewCreated_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics4, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics4>::remove_NewWebUIViewCreated>;
    NewWebUIViewCreated_revoker NewWebUIViewCreated(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler) const;
    void NewWebUIViewCreated(winrt::event_token const& token) const noexcept;
    winrt::event_token BackgroundActivated(Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler) const;
    using BackgroundActivated_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIActivationStatics4, &impl::abi_t<Windows::UI::WebUI::IWebUIActivationStatics4>::remove_BackgroundActivated>;
    BackgroundActivated_revoker BackgroundActivated(auto_revoke_t, Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler) const;
    void BackgroundActivated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::WebUI::IWebUIActivationStatics4> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstance
{
    bool Succeeded() const;
    void Succeeded(bool succeeded) const;
};
template <> struct consume<Windows::UI::WebUI::IWebUIBackgroundTaskInstance> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstance<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstanceStatics
{
    Windows::UI::WebUI::IWebUIBackgroundTaskInstance Current() const;
};
template <> struct consume<Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstanceStatics<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUINavigatedDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::UI::WebUI::IWebUINavigatedDeferral> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUINavigatedDeferral<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUINavigatedEventArgs
{
    Windows::UI::WebUI::WebUINavigatedOperation NavigatedOperation() const;
};
template <> struct consume<Windows::UI::WebUI::IWebUINavigatedEventArgs> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUINavigatedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUINavigatedOperation
{
    Windows::UI::WebUI::WebUINavigatedDeferral GetDeferral() const;
};
template <> struct consume<Windows::UI::WebUI::IWebUINavigatedOperation> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUINavigatedOperation<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIView
{
    int32_t ApplicationViewId() const;
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::Foundation::IInspectable> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIView, &impl::abi_t<Windows::UI::WebUI::IWebUIView>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::Foundation::IInspectable> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
    winrt::event_token Activated(Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const& handler) const;
    using Activated_revoker = impl::event_revoker<Windows::UI::WebUI::IWebUIView, &impl::abi_t<Windows::UI::WebUI::IWebUIView>::remove_Activated>;
    Activated_revoker Activated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const& handler) const;
    void Activated(winrt::event_token const& token) const noexcept;
    bool IgnoreApplicationContentUriRulesNavigationRestrictions() const;
    void IgnoreApplicationContentUriRulesNavigationRestrictions(bool value) const;
};
template <> struct consume<Windows::UI::WebUI::IWebUIView> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIView<D>; };

template <typename D>
struct consume_Windows_UI_WebUI_IWebUIViewStatics
{
    Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> CreateAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> CreateAsync(Windows::Foundation::Uri const& uri) const;
};
template <> struct consume<Windows::UI::WebUI::IWebUIViewStatics> { template <typename D> using type = consume_Windows_UI_WebUI_IWebUIViewStatics<D>; };

}
