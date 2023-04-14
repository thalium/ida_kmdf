// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Data.Xml.Dom.1.h"
#include "winrt/impl/Windows.Devices.Sms.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Networking.1.h"
#include "winrt/impl/Windows.Networking.Connectivity.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Networking.NetworkOperators.1.h"

WINRT_EXPORT namespace winrt::Windows::Networking::NetworkOperators {

struct ESimProfileInstallProgress
{
    int32_t TotalSizeInBytes;
    int32_t InstalledSizeInBytes;
};

inline bool operator==(ESimProfileInstallProgress const& left, ESimProfileInstallProgress const& right) noexcept
{
    return left.TotalSizeInBytes == right.TotalSizeInBytes && left.InstalledSizeInBytes == right.InstalledSizeInBytes;
}

inline bool operator!=(ESimProfileInstallProgress const& left, ESimProfileInstallProgress const& right) noexcept
{
    return !(left == right);
}

struct ProfileUsage
{
    uint32_t UsageInMegabytes;
    Windows::Foundation::DateTime LastSyncTime;
};

inline bool operator==(ProfileUsage const& left, ProfileUsage const& right) noexcept
{
    return left.UsageInMegabytes == right.UsageInMegabytes && left.LastSyncTime == right.LastSyncTime;
}

inline bool operator!=(ProfileUsage const& left, ProfileUsage const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Networking::NetworkOperators {

struct WINRT_EBO ESim :
    Windows::Networking::NetworkOperators::IESim,
    impl::require<ESim, Windows::Networking::NetworkOperators::IESim2>
{
    ESim(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimAddedEventArgs :
    Windows::Networking::NetworkOperators::IESimAddedEventArgs
{
    ESimAddedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimDiscoverEvent :
    Windows::Networking::NetworkOperators::IESimDiscoverEvent
{
    ESimDiscoverEvent(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimDiscoverResult :
    Windows::Networking::NetworkOperators::IESimDiscoverResult
{
    ESimDiscoverResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimDownloadProfileMetadataResult :
    Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult
{
    ESimDownloadProfileMetadataResult(std::nullptr_t) noexcept {}
};

struct ESimManager
{
    ESimManager() = delete;
    static Windows::Networking::NetworkOperators::ESimServiceInfo ServiceInfo();
    static Windows::Networking::NetworkOperators::ESimWatcher TryCreateESimWatcher();
    static winrt::event_token ServiceInfoChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using ServiceInfoChanged_revoker = impl::factory_event_revoker<Windows::Networking::NetworkOperators::IESimManagerStatics, &impl::abi_t<Windows::Networking::NetworkOperators::IESimManagerStatics>::remove_ServiceInfoChanged>;
    static ServiceInfoChanged_revoker ServiceInfoChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void ServiceInfoChanged(winrt::event_token const& token);
};

struct WINRT_EBO ESimOperationResult :
    Windows::Networking::NetworkOperators::IESimOperationResult
{
    ESimOperationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimPolicy :
    Windows::Networking::NetworkOperators::IESimPolicy
{
    ESimPolicy(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimProfile :
    Windows::Networking::NetworkOperators::IESimProfile
{
    ESimProfile(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimProfileMetadata :
    Windows::Networking::NetworkOperators::IESimProfileMetadata
{
    ESimProfileMetadata(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimProfilePolicy :
    Windows::Networking::NetworkOperators::IESimProfilePolicy
{
    ESimProfilePolicy(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimRemovedEventArgs :
    Windows::Networking::NetworkOperators::IESimRemovedEventArgs
{
    ESimRemovedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimServiceInfo :
    Windows::Networking::NetworkOperators::IESimServiceInfo
{
    ESimServiceInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimUpdatedEventArgs :
    Windows::Networking::NetworkOperators::IESimUpdatedEventArgs
{
    ESimUpdatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ESimWatcher :
    Windows::Networking::NetworkOperators::IESimWatcher
{
    ESimWatcher(std::nullptr_t) noexcept {}
};

struct FdnAccessManager
{
    FdnAccessManager() = delete;
    static Windows::Foundation::IAsyncOperation<bool> RequestUnlockAsync(param::hstring const& contactListId);
};

struct WINRT_EBO HotspotAuthenticationContext :
    Windows::Networking::NetworkOperators::IHotspotAuthenticationContext,
    impl::require<HotspotAuthenticationContext, Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>
{
    HotspotAuthenticationContext(std::nullptr_t) noexcept {}
    static bool TryGetAuthenticationContext(param::hstring const& evenToken, Windows::Networking::NetworkOperators::HotspotAuthenticationContext& context);
};

struct WINRT_EBO HotspotAuthenticationEventDetails :
    Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails
{
    HotspotAuthenticationEventDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HotspotCredentialsAuthenticationResult :
    Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult
{
    HotspotCredentialsAuthenticationResult(std::nullptr_t) noexcept {}
};

struct KnownCSimFilePaths
{
    KnownCSimFilePaths() = delete;
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid1();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid2();
};

struct KnownRuimFilePaths
{
    KnownRuimFilePaths() = delete;
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid1();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid2();
};

struct KnownSimFilePaths
{
    KnownSimFilePaths() = delete;
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFOns();
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid1();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid2();
};

struct KnownUSimFilePaths
{
    KnownUSimFilePaths() = delete;
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn();
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFOpl();
    static Windows::Foundation::Collections::IVectorView<uint32_t> EFPnn();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid1();
    static Windows::Foundation::Collections::IVectorView<uint32_t> Gid2();
};

struct WINRT_EBO MobileBroadbandAccount :
    Windows::Networking::NetworkOperators::IMobileBroadbandAccount,
    impl::require<MobileBroadbandAccount, Windows::Networking::NetworkOperators::IMobileBroadbandAccount2, Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>
{
    MobileBroadbandAccount(std::nullptr_t) noexcept {}
    static Windows::Foundation::Collections::IVectorView<hstring> AvailableNetworkAccountIds();
    static Windows::Networking::NetworkOperators::MobileBroadbandAccount CreateFromNetworkAccountId(param::hstring const& networkAccountId);
};

struct WINRT_EBO MobileBroadbandAccountEventArgs :
    Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs
{
    MobileBroadbandAccountEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandAccountUpdatedEventArgs :
    Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs
{
    MobileBroadbandAccountUpdatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandAccountWatcher :
    Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher
{
    MobileBroadbandAccountWatcher(std::nullptr_t) noexcept {}
    MobileBroadbandAccountWatcher();
};

struct WINRT_EBO MobileBroadbandAntennaSar :
    Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar
{
    MobileBroadbandAntennaSar(std::nullptr_t) noexcept {}
    MobileBroadbandAntennaSar(int32_t antennaIndex, int32_t sarBackoffIndex);
};

struct WINRT_EBO MobileBroadbandCellCdma :
    Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma
{
    MobileBroadbandCellCdma(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandCellGsm :
    Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm
{
    MobileBroadbandCellGsm(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandCellLte :
    Windows::Networking::NetworkOperators::IMobileBroadbandCellLte
{
    MobileBroadbandCellLte(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandCellTdscdma :
    Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma
{
    MobileBroadbandCellTdscdma(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandCellUmts :
    Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts
{
    MobileBroadbandCellUmts(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandCellsInfo :
    Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo
{
    MobileBroadbandCellsInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceInformation :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation,
    impl::require<MobileBroadbandDeviceInformation, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3>
{
    MobileBroadbandDeviceInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceService :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService
{
    MobileBroadbandDeviceService(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceServiceCommandResult :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult
{
    MobileBroadbandDeviceServiceCommandResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceServiceCommandSession :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession
{
    MobileBroadbandDeviceServiceCommandSession(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceServiceDataReceivedEventArgs :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs
{
    MobileBroadbandDeviceServiceDataReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceServiceDataSession :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession
{
    MobileBroadbandDeviceServiceDataSession(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceServiceInformation :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation
{
    MobileBroadbandDeviceServiceInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandDeviceServiceTriggerDetails :
    Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails
{
    MobileBroadbandDeviceServiceTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandModem :
    Windows::Networking::NetworkOperators::IMobileBroadbandModem,
    impl::require<MobileBroadbandModem, Windows::Networking::NetworkOperators::IMobileBroadbandModem2, Windows::Networking::NetworkOperators::IMobileBroadbandModem3>
{
    MobileBroadbandModem(std::nullptr_t) noexcept {}
    static hstring GetDeviceSelector();
    static Windows::Networking::NetworkOperators::MobileBroadbandModem FromId(param::hstring const& deviceId);
    static Windows::Networking::NetworkOperators::MobileBroadbandModem GetDefault();
};

struct WINRT_EBO MobileBroadbandModemConfiguration :
    Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration,
    impl::require<MobileBroadbandModemConfiguration, Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>
{
    MobileBroadbandModemConfiguration(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandModemIsolation :
    Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation
{
    MobileBroadbandModemIsolation(std::nullptr_t) noexcept {}
    MobileBroadbandModemIsolation(param::hstring const& modemDeviceId, param::hstring const& ruleGroupId);
};

struct WINRT_EBO MobileBroadbandNetwork :
    Windows::Networking::NetworkOperators::IMobileBroadbandNetwork,
    impl::require<MobileBroadbandNetwork, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>
{
    MobileBroadbandNetwork(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandNetworkRegistrationStateChange :
    Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange
{
    MobileBroadbandNetworkRegistrationStateChange(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandNetworkRegistrationStateChangeTriggerDetails :
    Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails
{
    MobileBroadbandNetworkRegistrationStateChangeTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPco :
    Windows::Networking::NetworkOperators::IMobileBroadbandPco
{
    MobileBroadbandPco(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPcoDataChangeTriggerDetails :
    Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails
{
    MobileBroadbandPcoDataChangeTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPin :
    Windows::Networking::NetworkOperators::IMobileBroadbandPin
{
    MobileBroadbandPin(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPinLockStateChange :
    Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange
{
    MobileBroadbandPinLockStateChange(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPinLockStateChangeTriggerDetails :
    Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails
{
    MobileBroadbandPinLockStateChangeTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPinManager :
    Windows::Networking::NetworkOperators::IMobileBroadbandPinManager
{
    MobileBroadbandPinManager(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandPinOperationResult :
    Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult
{
    MobileBroadbandPinOperationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandRadioStateChange :
    Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange
{
    MobileBroadbandRadioStateChange(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandRadioStateChangeTriggerDetails :
    Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails
{
    MobileBroadbandRadioStateChangeTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandSarManager :
    Windows::Networking::NetworkOperators::IMobileBroadbandSarManager
{
    MobileBroadbandSarManager(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandTransmissionStateChangedEventArgs :
    Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs
{
    MobileBroadbandTransmissionStateChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandUicc :
    Windows::Networking::NetworkOperators::IMobileBroadbandUicc
{
    MobileBroadbandUicc(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandUiccApp :
    Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp
{
    MobileBroadbandUiccApp(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandUiccAppReadRecordResult :
    Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult
{
    MobileBroadbandUiccAppReadRecordResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandUiccAppRecordDetailsResult :
    Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult
{
    MobileBroadbandUiccAppRecordDetailsResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MobileBroadbandUiccAppsResult :
    Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult
{
    MobileBroadbandUiccAppsResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO NetworkOperatorDataUsageTriggerDetails :
    Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails
{
    NetworkOperatorDataUsageTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO NetworkOperatorNotificationEventDetails :
    Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails,
    impl::require<NetworkOperatorNotificationEventDetails, Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>
{
    NetworkOperatorNotificationEventDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO NetworkOperatorTetheringAccessPointConfiguration :
    Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration
{
    NetworkOperatorTetheringAccessPointConfiguration(std::nullptr_t) noexcept {}
    NetworkOperatorTetheringAccessPointConfiguration();
};

struct WINRT_EBO NetworkOperatorTetheringClient :
    Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient
{
    NetworkOperatorTetheringClient(std::nullptr_t) noexcept {}
};

struct WINRT_EBO NetworkOperatorTetheringManager :
    Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager,
    impl::require<NetworkOperatorTetheringManager, Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>
{
    NetworkOperatorTetheringManager(std::nullptr_t) noexcept {}
    static Windows::Networking::NetworkOperators::TetheringCapability GetTetheringCapability(param::hstring const& networkAccountId);
    static Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager CreateFromNetworkAccountId(param::hstring const& networkAccountId);
    static Windows::Networking::NetworkOperators::TetheringCapability GetTetheringCapabilityFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile);
    static Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile);
    static Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile, Windows::Networking::Connectivity::NetworkAdapter const& adapter);
};

struct WINRT_EBO NetworkOperatorTetheringOperationResult :
    Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult
{
    NetworkOperatorTetheringOperationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProvisionFromXmlDocumentResults :
    Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults
{
    ProvisionFromXmlDocumentResults(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProvisionedProfile :
    Windows::Networking::NetworkOperators::IProvisionedProfile
{
    ProvisionedProfile(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProvisioningAgent :
    Windows::Networking::NetworkOperators::IProvisioningAgent
{
    ProvisioningAgent(std::nullptr_t) noexcept {}
    ProvisioningAgent();
    static Windows::Networking::NetworkOperators::ProvisioningAgent CreateFromNetworkAccountId(param::hstring const& networkAccountId);
};

struct WINRT_EBO TetheringEntitlementCheckTriggerDetails :
    Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails
{
    TetheringEntitlementCheckTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UssdMessage :
    Windows::Networking::NetworkOperators::IUssdMessage
{
    UssdMessage(std::nullptr_t) noexcept {}
    UssdMessage(param::hstring const& messageText);
};

struct WINRT_EBO UssdReply :
    Windows::Networking::NetworkOperators::IUssdReply
{
    UssdReply(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UssdSession :
    Windows::Networking::NetworkOperators::IUssdSession
{
    UssdSession(std::nullptr_t) noexcept {}
    static Windows::Networking::NetworkOperators::UssdSession CreateFromNetworkAccountId(param::hstring const& networkAccountId);
    static Windows::Networking::NetworkOperators::UssdSession CreateFromNetworkInterfaceId(param::hstring const& networkInterfaceId);
};

}
