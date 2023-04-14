// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Contacts.0.h"
#include "winrt/impl/Windows.Devices.Enumeration.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls {

struct WINRT_EBO ICallAnswerEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICallAnswerEventArgs>
{
    ICallAnswerEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICallRejectEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICallRejectEventArgs>
{
    ICallRejectEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICallStateChangeEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICallStateChangeEventArgs>
{
    ICallStateChangeEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILockScreenCallEndCallDeferral :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILockScreenCallEndCallDeferral>
{
    ILockScreenCallEndCallDeferral(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILockScreenCallEndRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILockScreenCallEndRequestedEventArgs>
{
    ILockScreenCallEndRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILockScreenCallUI :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILockScreenCallUI>
{
    ILockScreenCallUI(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMuteChangeEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMuteChangeEventArgs>
{
    IMuteChangeEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallBlockingStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallBlockingStatics>
{
    IPhoneCallBlockingStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryEntry :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryEntry>
{
    IPhoneCallHistoryEntry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryEntryAddress :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryEntryAddress>
{
    IPhoneCallHistoryEntryAddress(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryEntryAddressFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryEntryAddressFactory>
{
    IPhoneCallHistoryEntryAddressFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryEntryQueryOptions :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryEntryQueryOptions>
{
    IPhoneCallHistoryEntryQueryOptions(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryEntryReader :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryEntryReader>
{
    IPhoneCallHistoryEntryReader(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryManagerForUser :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryManagerForUser>
{
    IPhoneCallHistoryManagerForUser(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryManagerStatics>
{
    IPhoneCallHistoryManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryManagerStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryManagerStatics2>
{
    IPhoneCallHistoryManagerStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallHistoryStore :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallHistoryStore>
{
    IPhoneCallHistoryStore(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallManagerStatics>
{
    IPhoneCallManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallManagerStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallManagerStatics2>
{
    IPhoneCallManagerStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallStore :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallStore>
{
    IPhoneCallStore(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallVideoCapabilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallVideoCapabilities>
{
    IPhoneCallVideoCapabilities(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneCallVideoCapabilitiesManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneCallVideoCapabilitiesManagerStatics>
{
    IPhoneCallVideoCapabilitiesManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneDialOptions :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneDialOptions>
{
    IPhoneDialOptions(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLine :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLine>
{
    IPhoneLine(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLine2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLine2>
{
    IPhoneLine2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineCellularDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineCellularDetails>
{
    IPhoneLineCellularDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineConfiguration :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineConfiguration>
{
    IPhoneLineConfiguration(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineStatics>
{
    IPhoneLineStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineTransportDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineTransportDevice>
{
    IPhoneLineTransportDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineTransportDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineTransportDeviceStatics>
{
    IPhoneLineTransportDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineWatcher :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineWatcher>
{
    IPhoneLineWatcher(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneLineWatcherEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneLineWatcherEventArgs>
{
    IPhoneLineWatcherEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPhoneVoicemail :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPhoneVoicemail>
{
    IPhoneVoicemail(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVoipCallCoordinator :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipCallCoordinator>
{
    IVoipCallCoordinator(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVoipCallCoordinator2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipCallCoordinator2>,
    impl::require<IVoipCallCoordinator2, Windows::ApplicationModel::Calls::IVoipCallCoordinator>
{
    IVoipCallCoordinator2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVoipCallCoordinator3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipCallCoordinator3>,
    impl::require<IVoipCallCoordinator3, Windows::ApplicationModel::Calls::IVoipCallCoordinator>
{
    IVoipCallCoordinator3(std::nullptr_t = nullptr) noexcept {}
    using impl::consume_t<IVoipCallCoordinator3, Windows::ApplicationModel::Calls::IVoipCallCoordinator>::RequestNewIncomingCall;
    using impl::consume_t<IVoipCallCoordinator3, Windows::ApplicationModel::Calls::IVoipCallCoordinator3>::RequestNewIncomingCall;
};

struct WINRT_EBO IVoipCallCoordinator4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipCallCoordinator4>,
    impl::require<IVoipCallCoordinator4, Windows::ApplicationModel::Calls::IVoipCallCoordinator>
{
    IVoipCallCoordinator4(std::nullptr_t = nullptr) noexcept {}
    using impl::consume_t<IVoipCallCoordinator4, Windows::ApplicationModel::Calls::IVoipCallCoordinator>::ReserveCallResourcesAsync;
    using impl::consume_t<IVoipCallCoordinator4, Windows::ApplicationModel::Calls::IVoipCallCoordinator4>::ReserveCallResourcesAsync;
};

struct WINRT_EBO IVoipCallCoordinatorStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipCallCoordinatorStatics>
{
    IVoipCallCoordinatorStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVoipPhoneCall :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipPhoneCall>
{
    IVoipPhoneCall(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVoipPhoneCall2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipPhoneCall2>,
    impl::require<IVoipPhoneCall2, Windows::ApplicationModel::Calls::IVoipPhoneCall>
{
    IVoipPhoneCall2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVoipPhoneCall3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVoipPhoneCall3>,
    impl::require<IVoipPhoneCall3, Windows::ApplicationModel::Calls::IVoipPhoneCall, Windows::ApplicationModel::Calls::IVoipPhoneCall2>
{
    IVoipPhoneCall3(std::nullptr_t = nullptr) noexcept {}
};

}
