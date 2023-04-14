// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Data::Xml::Dom {

struct XmlDocument;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Sms {

enum class CellularClass;
struct ISmsMessage;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Networking {

struct HostName;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Connectivity {

enum class NetworkCostType;
struct ConnectionProfile;
struct NetworkAdapter;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;
struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::Networking::NetworkOperators {

enum class DataClasses : uint32_t
{
    None = 0x0,
    Gprs = 0x1,
    Edge = 0x2,
    Umts = 0x4,
    Hsdpa = 0x8,
    Hsupa = 0x10,
    LteAdvanced = 0x20,
    Cdma1xRtt = 0x10000,
    Cdma1xEvdo = 0x20000,
    Cdma1xEvdoRevA = 0x40000,
    Cdma1xEvdv = 0x80000,
    Cdma3xRtt = 0x100000,
    Cdma1xEvdoRevB = 0x200000,
    CdmaUmb = 0x400000,
    Custom = 0x80000000,
};

enum class ESimAuthenticationPreference : int32_t
{
    OnEntry = 0,
    OnAction = 1,
    Never = 2,
};

enum class ESimDiscoverResultKind : int32_t
{
    None = 0,
    Events = 1,
    ProfileMetadata = 2,
};

enum class ESimOperationStatus : int32_t
{
    Success = 0,
    NotAuthorized = 1,
    NotFound = 2,
    PolicyViolation = 3,
    InsufficientSpaceOnCard = 4,
    ServerFailure = 5,
    ServerNotReachable = 6,
    TimeoutWaitingForUserConsent = 7,
    IncorrectConfirmationCode = 8,
    ConfirmationCodeMaxRetriesExceeded = 9,
    CardRemoved = 10,
    CardBusy = 11,
    Other = 12,
    CardGeneralFailure = 13,
    ConfirmationCodeMissing = 14,
    InvalidMatchingId = 15,
    NoEligibleProfileForThisDevice = 16,
    OperationAborted = 17,
    EidMismatch = 18,
    ProfileNotAvailableForNewBinding = 19,
    ProfileNotReleasedByOperator = 20,
    OperationProhibitedByProfileClass = 21,
    ProfileNotPresent = 22,
    NoCorrespondingRequest = 23,
};

enum class ESimProfileClass : int32_t
{
    Operational = 0,
    Test = 1,
    Provisioning = 2,
};

enum class ESimProfileMetadataState : int32_t
{
    Unknown = 0,
    WaitingForInstall = 1,
    Downloading = 2,
    Installing = 3,
    Expired = 4,
    RejectingDownload = 5,
    NoLongerAvailable = 6,
    DeniedByPolicy = 7,
};

enum class ESimProfileState : int32_t
{
    Unknown = 0,
    Disabled = 1,
    Enabled = 2,
    Deleted = 3,
};

enum class ESimState : int32_t
{
    Unknown = 0,
    Idle = 1,
    Removed = 2,
    Busy = 3,
};

enum class ESimWatcherStatus : int32_t
{
    Created = 0,
    Started = 1,
    EnumerationCompleted = 2,
    Stopping = 3,
    Stopped = 4,
};

enum class HotspotAuthenticationResponseCode : int32_t
{
    NoError = 0,
    LoginSucceeded = 50,
    LoginFailed = 100,
    RadiusServerError = 102,
    NetworkAdministratorError = 105,
    LoginAborted = 151,
    AccessGatewayInternalError = 255,
};

enum class MobileBroadbandAccountWatcherStatus : int32_t
{
    Created = 0,
    Started = 1,
    EnumerationCompleted = 2,
    Stopped = 3,
    Aborted = 4,
};

enum class MobileBroadbandDeviceType : int32_t
{
    Unknown = 0,
    Embedded = 1,
    Removable = 2,
    Remote = 3,
};

enum class MobileBroadbandModemStatus : int32_t
{
    Success = 0,
    OtherFailure = 1,
    Busy = 2,
    NoDeviceSupport = 3,
};

enum class MobileBroadbandPinFormat : int32_t
{
    Unknown = 0,
    Numeric = 1,
    Alphanumeric = 2,
};

enum class MobileBroadbandPinLockState : int32_t
{
    Unknown = 0,
    Unlocked = 1,
    PinRequired = 2,
    PinUnblockKeyRequired = 3,
};

enum class MobileBroadbandPinType : int32_t
{
    None = 0,
    Custom = 1,
    Pin1 = 2,
    Pin2 = 3,
    SimPin = 4,
    FirstSimPin = 5,
    NetworkPin = 6,
    NetworkSubsetPin = 7,
    ServiceProviderPin = 8,
    CorporatePin = 9,
    SubsidyLock = 10,
};

enum class MobileBroadbandRadioState : int32_t
{
    Off = 0,
    On = 1,
};

enum class MobileBroadbandUiccAppOperationStatus : int32_t
{
    Success = 0,
    InvalidUiccFilePath = 1,
    AccessConditionNotHeld = 2,
    UiccBusy = 3,
};

enum class NetworkDeviceStatus : int32_t
{
    DeviceNotReady = 0,
    DeviceReady = 1,
    SimNotInserted = 2,
    BadSim = 3,
    DeviceHardwareFailure = 4,
    AccountNotActivated = 5,
    DeviceLocked = 6,
    DeviceBlocked = 7,
};

enum class NetworkOperatorDataUsageNotificationKind : int32_t
{
    DataUsageProgress = 0,
};

enum class NetworkOperatorEventMessageType : int32_t
{
    Gsm = 0,
    Cdma = 1,
    Ussd = 2,
    DataPlanThresholdReached = 3,
    DataPlanReset = 4,
    DataPlanDeleted = 5,
    ProfileConnected = 6,
    ProfileDisconnected = 7,
    RegisteredRoaming = 8,
    RegisteredHome = 9,
    TetheringEntitlementCheck = 10,
    TetheringOperationalStateChanged = 11,
    TetheringNumberOfClientsChanged = 12,
};

enum class NetworkRegistrationState : int32_t
{
    None = 0,
    Deregistered = 1,
    Searching = 2,
    Home = 3,
    Roaming = 4,
    Partner = 5,
    Denied = 6,
};

enum class ProfileMediaType : int32_t
{
    Wlan = 0,
    Wwan = 1,
};

enum class TetheringCapability : int32_t
{
    Enabled = 0,
    DisabledByGroupPolicy = 1,
    DisabledByHardwareLimitation = 2,
    DisabledByOperator = 3,
    DisabledBySku = 4,
    DisabledByRequiredAppNotInstalled = 5,
    DisabledDueToUnknownCause = 6,
    DisabledBySystemCapability = 7,
};

enum class TetheringOperationStatus : int32_t
{
    Success = 0,
    Unknown = 1,
    MobileBroadbandDeviceOff = 2,
    WiFiDeviceOff = 3,
    EntitlementCheckTimeout = 4,
    EntitlementCheckFailure = 5,
    OperationInProgress = 6,
    BluetoothDeviceOff = 7,
    NetworkLimitedConnectivity = 8,
};

enum class TetheringOperationalState : int32_t
{
    Unknown = 0,
    On = 1,
    Off = 2,
    InTransition = 3,
};

enum class UiccAccessCondition : int32_t
{
    AlwaysAllowed = 0,
    Pin1 = 1,
    Pin2 = 2,
    Pin3 = 3,
    Pin4 = 4,
    Administrative5 = 5,
    Administrative6 = 6,
    NeverAllowed = 7,
};

enum class UiccAppKind : int32_t
{
    Unknown = 0,
    MF = 1,
    MFSim = 2,
    MFRuim = 3,
    USim = 4,
    CSim = 5,
    ISim = 6,
};

enum class UiccAppRecordKind : int32_t
{
    Unknown = 0,
    Transparent = 1,
    RecordOriented = 2,
};

enum class UssdResultCode : int32_t
{
    NoActionRequired = 0,
    ActionRequired = 1,
    Terminated = 2,
    OtherLocalClient = 3,
    OperationNotSupported = 4,
    NetworkTimeout = 5,
};

struct IESim;
struct IESim2;
struct IESimAddedEventArgs;
struct IESimDiscoverEvent;
struct IESimDiscoverResult;
struct IESimDownloadProfileMetadataResult;
struct IESimManagerStatics;
struct IESimOperationResult;
struct IESimPolicy;
struct IESimProfile;
struct IESimProfileMetadata;
struct IESimProfilePolicy;
struct IESimRemovedEventArgs;
struct IESimServiceInfo;
struct IESimUpdatedEventArgs;
struct IESimWatcher;
struct IFdnAccessManagerStatics;
struct IHotspotAuthenticationContext;
struct IHotspotAuthenticationContext2;
struct IHotspotAuthenticationContextStatics;
struct IHotspotAuthenticationEventDetails;
struct IHotspotCredentialsAuthenticationResult;
struct IKnownCSimFilePathsStatics;
struct IKnownRuimFilePathsStatics;
struct IKnownSimFilePathsStatics;
struct IKnownUSimFilePathsStatics;
struct IMobileBroadbandAccount;
struct IMobileBroadbandAccount2;
struct IMobileBroadbandAccount3;
struct IMobileBroadbandAccountEventArgs;
struct IMobileBroadbandAccountStatics;
struct IMobileBroadbandAccountUpdatedEventArgs;
struct IMobileBroadbandAccountWatcher;
struct IMobileBroadbandAntennaSar;
struct IMobileBroadbandAntennaSarFactory;
struct IMobileBroadbandCellCdma;
struct IMobileBroadbandCellGsm;
struct IMobileBroadbandCellLte;
struct IMobileBroadbandCellTdscdma;
struct IMobileBroadbandCellUmts;
struct IMobileBroadbandCellsInfo;
struct IMobileBroadbandDeviceInformation;
struct IMobileBroadbandDeviceInformation2;
struct IMobileBroadbandDeviceInformation3;
struct IMobileBroadbandDeviceService;
struct IMobileBroadbandDeviceServiceCommandResult;
struct IMobileBroadbandDeviceServiceCommandSession;
struct IMobileBroadbandDeviceServiceDataReceivedEventArgs;
struct IMobileBroadbandDeviceServiceDataSession;
struct IMobileBroadbandDeviceServiceInformation;
struct IMobileBroadbandDeviceServiceTriggerDetails;
struct IMobileBroadbandModem;
struct IMobileBroadbandModem2;
struct IMobileBroadbandModem3;
struct IMobileBroadbandModemConfiguration;
struct IMobileBroadbandModemConfiguration2;
struct IMobileBroadbandModemIsolation;
struct IMobileBroadbandModemIsolationFactory;
struct IMobileBroadbandModemStatics;
struct IMobileBroadbandNetwork;
struct IMobileBroadbandNetwork2;
struct IMobileBroadbandNetwork3;
struct IMobileBroadbandNetworkRegistrationStateChange;
struct IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails;
struct IMobileBroadbandPco;
struct IMobileBroadbandPcoDataChangeTriggerDetails;
struct IMobileBroadbandPin;
struct IMobileBroadbandPinLockStateChange;
struct IMobileBroadbandPinLockStateChangeTriggerDetails;
struct IMobileBroadbandPinManager;
struct IMobileBroadbandPinOperationResult;
struct IMobileBroadbandRadioStateChange;
struct IMobileBroadbandRadioStateChangeTriggerDetails;
struct IMobileBroadbandSarManager;
struct IMobileBroadbandTransmissionStateChangedEventArgs;
struct IMobileBroadbandUicc;
struct IMobileBroadbandUiccApp;
struct IMobileBroadbandUiccAppReadRecordResult;
struct IMobileBroadbandUiccAppRecordDetailsResult;
struct IMobileBroadbandUiccAppsResult;
struct INetworkOperatorDataUsageTriggerDetails;
struct INetworkOperatorNotificationEventDetails;
struct INetworkOperatorTetheringAccessPointConfiguration;
struct INetworkOperatorTetheringClient;
struct INetworkOperatorTetheringClientManager;
struct INetworkOperatorTetheringEntitlementCheck;
struct INetworkOperatorTetheringManager;
struct INetworkOperatorTetheringManagerStatics;
struct INetworkOperatorTetheringManagerStatics2;
struct INetworkOperatorTetheringManagerStatics3;
struct INetworkOperatorTetheringOperationResult;
struct IProvisionFromXmlDocumentResults;
struct IProvisionedProfile;
struct IProvisioningAgent;
struct IProvisioningAgentStaticMethods;
struct ITetheringEntitlementCheckTriggerDetails;
struct IUssdMessage;
struct IUssdMessageFactory;
struct IUssdReply;
struct IUssdSession;
struct IUssdSessionStatics;
struct ESim;
struct ESimAddedEventArgs;
struct ESimDiscoverEvent;
struct ESimDiscoverResult;
struct ESimDownloadProfileMetadataResult;
struct ESimManager;
struct ESimOperationResult;
struct ESimPolicy;
struct ESimProfile;
struct ESimProfileMetadata;
struct ESimProfilePolicy;
struct ESimRemovedEventArgs;
struct ESimServiceInfo;
struct ESimUpdatedEventArgs;
struct ESimWatcher;
struct FdnAccessManager;
struct HotspotAuthenticationContext;
struct HotspotAuthenticationEventDetails;
struct HotspotCredentialsAuthenticationResult;
struct KnownCSimFilePaths;
struct KnownRuimFilePaths;
struct KnownSimFilePaths;
struct KnownUSimFilePaths;
struct MobileBroadbandAccount;
struct MobileBroadbandAccountEventArgs;
struct MobileBroadbandAccountUpdatedEventArgs;
struct MobileBroadbandAccountWatcher;
struct MobileBroadbandAntennaSar;
struct MobileBroadbandCellCdma;
struct MobileBroadbandCellGsm;
struct MobileBroadbandCellLte;
struct MobileBroadbandCellTdscdma;
struct MobileBroadbandCellUmts;
struct MobileBroadbandCellsInfo;
struct MobileBroadbandDeviceInformation;
struct MobileBroadbandDeviceService;
struct MobileBroadbandDeviceServiceCommandResult;
struct MobileBroadbandDeviceServiceCommandSession;
struct MobileBroadbandDeviceServiceDataReceivedEventArgs;
struct MobileBroadbandDeviceServiceDataSession;
struct MobileBroadbandDeviceServiceInformation;
struct MobileBroadbandDeviceServiceTriggerDetails;
struct MobileBroadbandModem;
struct MobileBroadbandModemConfiguration;
struct MobileBroadbandModemIsolation;
struct MobileBroadbandNetwork;
struct MobileBroadbandNetworkRegistrationStateChange;
struct MobileBroadbandNetworkRegistrationStateChangeTriggerDetails;
struct MobileBroadbandPco;
struct MobileBroadbandPcoDataChangeTriggerDetails;
struct MobileBroadbandPin;
struct MobileBroadbandPinLockStateChange;
struct MobileBroadbandPinLockStateChangeTriggerDetails;
struct MobileBroadbandPinManager;
struct MobileBroadbandPinOperationResult;
struct MobileBroadbandRadioStateChange;
struct MobileBroadbandRadioStateChangeTriggerDetails;
struct MobileBroadbandSarManager;
struct MobileBroadbandTransmissionStateChangedEventArgs;
struct MobileBroadbandUicc;
struct MobileBroadbandUiccApp;
struct MobileBroadbandUiccAppReadRecordResult;
struct MobileBroadbandUiccAppRecordDetailsResult;
struct MobileBroadbandUiccAppsResult;
struct NetworkOperatorDataUsageTriggerDetails;
struct NetworkOperatorNotificationEventDetails;
struct NetworkOperatorTetheringAccessPointConfiguration;
struct NetworkOperatorTetheringClient;
struct NetworkOperatorTetheringManager;
struct NetworkOperatorTetheringOperationResult;
struct ProvisionFromXmlDocumentResults;
struct ProvisionedProfile;
struct ProvisioningAgent;
struct TetheringEntitlementCheckTriggerDetails;
struct UssdMessage;
struct UssdReply;
struct UssdSession;
struct ESimProfileInstallProgress;
struct ProfileUsage;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Networking::NetworkOperators::DataClasses> : std::true_type {};
template <> struct category<Windows::Networking::NetworkOperators::IESim>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESim2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimAddedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimDiscoverEvent>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimDiscoverResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimOperationResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimPolicy>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimProfile>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimProfileMetadata>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimProfilePolicy>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimRemovedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimServiceInfo>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IESimWatcher>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IFdnAccessManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccount>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccount2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandCellLte>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModem>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModem2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModem3>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPco>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPin>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPinManager>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandUicc>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IProvisionedProfile>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IProvisioningAgent>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IUssdMessage>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IUssdMessageFactory>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IUssdReply>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IUssdSession>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::IUssdSessionStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESim>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimAddedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimDiscoverEvent>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimDiscoverResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimManager>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimOperationResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimPolicy>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfile>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfileMetadata>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfilePolicy>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimRemovedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimServiceInfo>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimWatcher>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::FdnAccessManager>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::HotspotAuthenticationContext>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::HotspotAuthenticationEventDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::KnownCSimFilePaths>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::KnownRuimFilePaths>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::KnownSimFilePaths>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::KnownUSimFilePaths>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandAccount>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceService>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandModem>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandNetwork>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPco>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPcoDataChangeTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPin>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChangeTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinManager>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChangeTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandSarManager>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandUicc>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorDataUsageTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorNotificationEventDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ProvisionedProfile>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::ProvisioningAgent>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::TetheringEntitlementCheckTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::UssdMessage>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::UssdReply>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::UssdSession>{ using type = class_category; };
template <> struct category<Windows::Networking::NetworkOperators::DataClasses>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimAuthenticationPreference>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimDiscoverResultKind>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimOperationStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfileClass>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfileMetadataState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfileState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimWatcherStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandDeviceType>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinFormat>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinLockState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandPinType>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandRadioState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkDeviceStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::NetworkRegistrationState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ProfileMediaType>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::TetheringCapability>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::TetheringOperationStatus>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::TetheringOperationalState>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::UiccAccessCondition>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::UiccAppKind>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::UiccAppRecordKind>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::UssdResultCode>{ using type = enum_category; };
template <> struct category<Windows::Networking::NetworkOperators::ESimProfileInstallProgress>{ using type = struct_category<int32_t,int32_t>; };
template <> struct category<Windows::Networking::NetworkOperators::ProfileUsage>{ using type = struct_category<uint32_t,Windows::Foundation::DateTime>; };
template <> struct name<Windows::Networking::NetworkOperators::IESim>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESim" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESim2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESim2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimAddedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimAddedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimDiscoverEvent>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimDiscoverEvent" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimDiscoverResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimDiscoverResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimDownloadProfileMetadataResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimManagerStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimManagerStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimOperationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimOperationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimPolicy>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimPolicy" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimProfile>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimProfile" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimProfileMetadata>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimProfileMetadata" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimProfilePolicy>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimProfilePolicy" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimRemovedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimRemovedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimServiceInfo>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimServiceInfo" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimUpdatedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IESimWatcher>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IESimWatcher" }; };
template <> struct name<Windows::Networking::NetworkOperators::IFdnAccessManagerStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IFdnAccessManagerStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IHotspotAuthenticationContext" }; };
template <> struct name<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IHotspotAuthenticationContext2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IHotspotAuthenticationContextStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IHotspotAuthenticationEventDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IHotspotCredentialsAuthenticationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IKnownCSimFilePathsStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IKnownRuimFilePathsStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IKnownSimFilePathsStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IKnownUSimFilePathsStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccount>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccount" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccount2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccount2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccount3" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccountEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccountStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccountUpdatedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAccountWatcher" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAntennaSar" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandAntennaSarFactory" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandCellCdma" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandCellGsm" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandCellLte>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandCellLte" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandCellTdscdma" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandCellUmts" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandCellsInfo" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceInformation" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceInformation2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceInformation3" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceService" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceServiceCommandResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceServiceCommandSession" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceServiceDataReceivedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceServiceDataSession" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceServiceInformation" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandDeviceServiceTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModem>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModem" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModem2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModem2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModem3>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModem3" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModemConfiguration" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModemConfiguration2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModemIsolation" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModemIsolationFactory" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandModemStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandNetwork" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandNetwork2" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandNetwork3" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandNetworkRegistrationStateChange" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPco>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPco" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPcoDataChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPin>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPin" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPinLockStateChange" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPinLockStateChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPinManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPinManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandPinOperationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandRadioStateChange" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandRadioStateChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandSarManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandTransmissionStateChangedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandUicc>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandUicc" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandUiccApp" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandUiccAppReadRecordResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandUiccAppRecordDetailsResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IMobileBroadbandUiccAppsResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorDataUsageTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorNotificationEventDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringAccessPointConfiguration" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringClient" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringClientManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringEntitlementCheck" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringManagerStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringManagerStatics2" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringManagerStatics3" }; };
template <> struct name<Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.INetworkOperatorTetheringOperationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IProvisionFromXmlDocumentResults" }; };
template <> struct name<Windows::Networking::NetworkOperators::IProvisionedProfile>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IProvisionedProfile" }; };
template <> struct name<Windows::Networking::NetworkOperators::IProvisioningAgent>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IProvisioningAgent" }; };
template <> struct name<Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IProvisioningAgentStaticMethods" }; };
template <> struct name<Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ITetheringEntitlementCheckTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::IUssdMessage>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IUssdMessage" }; };
template <> struct name<Windows::Networking::NetworkOperators::IUssdMessageFactory>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IUssdMessageFactory" }; };
template <> struct name<Windows::Networking::NetworkOperators::IUssdReply>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IUssdReply" }; };
template <> struct name<Windows::Networking::NetworkOperators::IUssdSession>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IUssdSession" }; };
template <> struct name<Windows::Networking::NetworkOperators::IUssdSessionStatics>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.IUssdSessionStatics" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESim>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESim" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimAddedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimAddedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimDiscoverEvent>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimDiscoverEvent" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimDiscoverResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimDiscoverResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimDownloadProfileMetadataResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimOperationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimOperationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimPolicy>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimPolicy" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfile>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfile" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfileMetadata>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfileMetadata" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfilePolicy>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfilePolicy" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimRemovedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimRemovedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimServiceInfo>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimServiceInfo" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimUpdatedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimWatcher>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimWatcher" }; };
template <> struct name<Windows::Networking::NetworkOperators::FdnAccessManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.FdnAccessManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::HotspotAuthenticationContext>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.HotspotAuthenticationContext" }; };
template <> struct name<Windows::Networking::NetworkOperators::HotspotAuthenticationEventDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.HotspotAuthenticationEventDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.HotspotCredentialsAuthenticationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::KnownCSimFilePaths>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.KnownCSimFilePaths" }; };
template <> struct name<Windows::Networking::NetworkOperators::KnownRuimFilePaths>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.KnownRuimFilePaths" }; };
template <> struct name<Windows::Networking::NetworkOperators::KnownSimFilePaths>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.KnownSimFilePaths" }; };
template <> struct name<Windows::Networking::NetworkOperators::KnownUSimFilePaths>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.KnownUSimFilePaths" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandAccount>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandAccount" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandAccountEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandAccountUpdatedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandAccountWatcher" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandAntennaSar" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandCellCdma" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandCellGsm" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandCellLte" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandCellTdscdma" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandCellUmts" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandCellsInfo" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceInformation" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceService>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceService" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceServiceCommandResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceServiceCommandSession" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceServiceDataReceivedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceServiceDataSession" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceServiceInformation" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceServiceTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandModem>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandModem" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandModemConfiguration" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandModemIsolation" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandNetwork>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandNetwork" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandNetworkRegistrationStateChange" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandNetworkRegistrationStateChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPco>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPco" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPcoDataChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPcoDataChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPin>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPin" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinLockStateChange" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinLockStateChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinOperationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandRadioStateChange" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandRadioStateChangeTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandSarManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandSarManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandTransmissionStateChangedEventArgs" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandUicc>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandUicc" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandUiccApp" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandUiccAppReadRecordResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandUiccAppRecordDetailsResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandUiccAppsResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorDataUsageTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorDataUsageTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorNotificationEventDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorNotificationEventDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorTetheringAccessPointConfiguration" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorTetheringClient" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult" }; };
template <> struct name<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ProvisionFromXmlDocumentResults" }; };
template <> struct name<Windows::Networking::NetworkOperators::ProvisionedProfile>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ProvisionedProfile" }; };
template <> struct name<Windows::Networking::NetworkOperators::ProvisioningAgent>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ProvisioningAgent" }; };
template <> struct name<Windows::Networking::NetworkOperators::TetheringEntitlementCheckTriggerDetails>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.TetheringEntitlementCheckTriggerDetails" }; };
template <> struct name<Windows::Networking::NetworkOperators::UssdMessage>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UssdMessage" }; };
template <> struct name<Windows::Networking::NetworkOperators::UssdReply>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UssdReply" }; };
template <> struct name<Windows::Networking::NetworkOperators::UssdSession>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UssdSession" }; };
template <> struct name<Windows::Networking::NetworkOperators::DataClasses>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.DataClasses" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimAuthenticationPreference>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimAuthenticationPreference" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimDiscoverResultKind>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimDiscoverResultKind" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimOperationStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimOperationStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfileClass>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfileClass" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfileMetadataState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfileMetadataState" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfileState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfileState" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimState" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimWatcherStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimWatcherStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.HotspotAuthenticationResponseCode" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandAccountWatcherStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandDeviceType>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandDeviceType" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandModemStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinFormat>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinFormat" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinLockState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinLockState" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandPinType>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandPinType" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandRadioState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandRadioState" }; };
template <> struct name<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.MobileBroadbandUiccAppOperationStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkDeviceStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkDeviceStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorDataUsageNotificationKind" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkOperatorEventMessageType" }; };
template <> struct name<Windows::Networking::NetworkOperators::NetworkRegistrationState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.NetworkRegistrationState" }; };
template <> struct name<Windows::Networking::NetworkOperators::ProfileMediaType>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ProfileMediaType" }; };
template <> struct name<Windows::Networking::NetworkOperators::TetheringCapability>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.TetheringCapability" }; };
template <> struct name<Windows::Networking::NetworkOperators::TetheringOperationStatus>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.TetheringOperationStatus" }; };
template <> struct name<Windows::Networking::NetworkOperators::TetheringOperationalState>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.TetheringOperationalState" }; };
template <> struct name<Windows::Networking::NetworkOperators::UiccAccessCondition>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UiccAccessCondition" }; };
template <> struct name<Windows::Networking::NetworkOperators::UiccAppKind>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UiccAppKind" }; };
template <> struct name<Windows::Networking::NetworkOperators::UiccAppRecordKind>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UiccAppRecordKind" }; };
template <> struct name<Windows::Networking::NetworkOperators::UssdResultCode>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.UssdResultCode" }; };
template <> struct name<Windows::Networking::NetworkOperators::ESimProfileInstallProgress>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ESimProfileInstallProgress" }; };
template <> struct name<Windows::Networking::NetworkOperators::ProfileUsage>{ static constexpr auto & value{ L"Windows.Networking.NetworkOperators.ProfileUsage" }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESim>{ static constexpr guid value{ 0x6F6E6E26,0xF123,0x437D,{ 0x8C,0xED,0xDC,0x1D,0x2B,0xC0,0xC3,0xA9 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESim2>{ static constexpr guid value{ 0xBD4FD0A0,0xC68F,0x56EB,{ 0xB9,0x9B,0x8F,0x34,0xB8,0x10,0x02,0x99 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimAddedEventArgs>{ static constexpr guid value{ 0x38BD0A58,0x4D5A,0x4D08,{ 0x8D,0xA7,0xE7,0x3E,0xFF,0x36,0x9D,0xDD } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimDiscoverEvent>{ static constexpr guid value{ 0xE59AC3E3,0x39BC,0x5F6F,{ 0x93,0x21,0x0D,0x4A,0x18,0x2D,0x26,0x1B } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimDiscoverResult>{ static constexpr guid value{ 0x56B4BB5E,0xAB2F,0x5AC6,{ 0xB3,0x59,0xDD,0x5A,0x8E,0x23,0x79,0x26 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult>{ static constexpr guid value{ 0xC4234D9E,0x5AD6,0x426D,{ 0x8D,0x00,0x44,0x34,0xF4,0x49,0xAF,0xEC } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimManagerStatics>{ static constexpr guid value{ 0x0BFA2C0C,0xDF88,0x4631,{ 0xBF,0x04,0xC1,0x2E,0x28,0x1B,0x39,0x62 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimOperationResult>{ static constexpr guid value{ 0xA67B63B1,0x309B,0x4E77,{ 0x9E,0x7E,0xCD,0x93,0xF1,0xDD,0xC7,0xB9 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimPolicy>{ static constexpr guid value{ 0x41E1B99D,0xCF7E,0x4315,{ 0x88,0x2B,0x6F,0x1E,0x74,0xB0,0xD3,0x8F } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimProfile>{ static constexpr guid value{ 0xEE1E7880,0x06A9,0x4027,{ 0xB4,0xF8,0xDD,0xB2,0x3D,0x78,0x10,0xE0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimProfileMetadata>{ static constexpr guid value{ 0xED25831F,0x90DB,0x498D,{ 0xA7,0xB4,0xEB,0xCE,0x80,0x7D,0x3C,0x23 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimProfilePolicy>{ static constexpr guid value{ 0xE6DD0F1D,0x9C5C,0x46C5,{ 0xA2,0x89,0xA9,0x48,0x99,0x9B,0xF0,0x62 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimRemovedEventArgs>{ static constexpr guid value{ 0xDEC5277B,0x2FD9,0x4ED9,{ 0x83,0x76,0xD9,0xB5,0xE4,0x12,0x78,0xA3 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimServiceInfo>{ static constexpr guid value{ 0xF16AABCF,0x7F59,0x4A51,{ 0x84,0x94,0xBD,0x89,0xD5,0xFF,0x50,0xEE } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimUpdatedEventArgs>{ static constexpr guid value{ 0x4C125CEC,0x508D,0x4B88,{ 0x83,0xCB,0x68,0xBE,0xF8,0x16,0x8D,0x12 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IESimWatcher>{ static constexpr guid value{ 0xC1F84CEB,0xA28D,0x4FBF,{ 0x97,0x71,0x6E,0x31,0xB8,0x1C,0xCF,0x22 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IFdnAccessManagerStatics>{ static constexpr guid value{ 0xF2AA4395,0xF1E6,0x4319,{ 0xAA,0x3E,0x47,0x7C,0xA6,0x4B,0x2B,0xDF } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext>{ static constexpr guid value{ 0xE756C791,0x1003,0x4DE5,{ 0x83,0xC7,0xDE,0x61,0xD8,0x88,0x31,0xD0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>{ static constexpr guid value{ 0xE756C791,0x1004,0x4DE5,{ 0x83,0xC7,0xDE,0x61,0xD8,0x88,0x31,0xD0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics>{ static constexpr guid value{ 0xE756C791,0x1002,0x4DE5,{ 0x83,0xC7,0xDE,0x61,0xD8,0x88,0x31,0xD0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails>{ static constexpr guid value{ 0xE756C791,0x1001,0x4DE5,{ 0x83,0xC7,0xDE,0x61,0xD8,0x88,0x31,0xD0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult>{ static constexpr guid value{ 0xE756C791,0x1005,0x4DE5,{ 0x83,0xC7,0xDE,0x61,0xD8,0x88,0x31,0xD0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>{ static constexpr guid value{ 0xB458AEED,0x49F1,0x4C22,{ 0xB0,0x73,0x96,0xD5,0x11,0xBF,0x9C,0x35 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>{ static constexpr guid value{ 0x3883C8B9,0xFF24,0x4571,{ 0xA8,0x67,0x09,0xF9,0x60,0x42,0x6E,0x14 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>{ static constexpr guid value{ 0x80CD1A63,0x37A5,0x43D3,{ 0x80,0xA3,0xCC,0xD2,0x3E,0x8F,0xEC,0xEE } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>{ static constexpr guid value{ 0x7C34E581,0x1F1B,0x43F4,{ 0x95,0x30,0x8B,0x09,0x2D,0x32,0xD7,0x1F } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccount>{ static constexpr guid value{ 0x36C24CCD,0xCEE2,0x43E0,{ 0xA6,0x03,0xEE,0x86,0xA3,0x6D,0x65,0x70 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccount2>{ static constexpr guid value{ 0x38F52F1C,0x1136,0x4257,{ 0x95,0x9F,0xB6,0x58,0xA3,0x52,0xB6,0xD4 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>{ static constexpr guid value{ 0x092A1E21,0x9379,0x4B9B,{ 0xAD,0x31,0xD5,0xFE,0xE2,0xF7,0x48,0xC6 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs>{ static constexpr guid value{ 0x3853C880,0x77DE,0x4C04,{ 0xBE,0xAD,0xA1,0x23,0xB0,0x8C,0x9F,0x59 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>{ static constexpr guid value{ 0xAA7F4D24,0xAFC1,0x4FC8,{ 0xAE,0x9A,0xA9,0x17,0x53,0x10,0xFA,0xAD } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs>{ static constexpr guid value{ 0x7BC31D88,0xA6BD,0x49E1,{ 0x80,0xAB,0x6B,0x91,0x35,0x4A,0x57,0xD4 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>{ static constexpr guid value{ 0x6BF3335E,0x23B5,0x449F,{ 0x92,0x8D,0x5E,0x0D,0x3E,0x04,0x47,0x1D } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar>{ static constexpr guid value{ 0xB9AF4B7E,0xCBF9,0x4109,{ 0x90,0xBE,0x5C,0x06,0xBF,0xD5,0x13,0xB6 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory>{ static constexpr guid value{ 0xA91E1716,0xC04D,0x4A21,{ 0x86,0x98,0x14,0x59,0xDC,0x67,0x2C,0x6E } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma>{ static constexpr guid value{ 0x0601B3B4,0x411A,0x4F2E,{ 0x82,0x87,0x76,0xF5,0x65,0x0C,0x60,0xCD } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm>{ static constexpr guid value{ 0xCC917F06,0x7EE0,0x47B8,{ 0x9E,0x1F,0xC3,0xB4,0x8D,0xF9,0xDF,0x5B } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandCellLte>{ static constexpr guid value{ 0x9197C87B,0x2B78,0x456D,{ 0x8B,0x53,0xAA,0xA2,0x5D,0x0A,0xF7,0x41 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma>{ static constexpr guid value{ 0x0EDA1655,0xDB0E,0x4182,{ 0x8C,0xDA,0xCC,0x41,0x9A,0x7B,0xDE,0x08 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts>{ static constexpr guid value{ 0x77B4B5AE,0x49C8,0x4F15,{ 0xB2,0x85,0x4C,0x26,0xA7,0xF6,0x72,0x15 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo>{ static constexpr guid value{ 0x89A9562A,0xE472,0x4DA5,{ 0x92,0x9C,0xDE,0x61,0x71,0x1D,0xD2,0x61 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation>{ static constexpr guid value{ 0xE6D08168,0xE381,0x4C6E,{ 0x9B,0xE8,0xFE,0x15,0x69,0x69,0xA4,0x46 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2>{ static constexpr guid value{ 0x2E467AF1,0xF932,0x4737,{ 0xA7,0x22,0x03,0xBA,0x72,0x37,0x0C,0xB8 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3>{ static constexpr guid value{ 0xE08BB4BD,0x5D30,0x4B5A,{ 0x92,0xCC,0xD5,0x4D,0xF8,0x81,0xD4,0x9E } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService>{ static constexpr guid value{ 0x22BE1A52,0xBD80,0x40AC,{ 0x8E,0x1F,0x2E,0x07,0x83,0x6A,0x3D,0xBD } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult>{ static constexpr guid value{ 0xB0F46ABB,0x94D6,0x44B9,{ 0xA5,0x38,0xF0,0x81,0x0B,0x64,0x53,0x89 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession>{ static constexpr guid value{ 0xFC098A45,0x913B,0x4914,{ 0xB6,0xC3,0xAE,0x63,0x04,0x59,0x3E,0x75 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs>{ static constexpr guid value{ 0xB6AA13DE,0x1380,0x40E3,{ 0x86,0x18,0x73,0xCB,0xCA,0x48,0x13,0x8C } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession>{ static constexpr guid value{ 0xDAD62333,0x8BCF,0x4289,{ 0x8A,0x37,0x04,0x5C,0x21,0x69,0x48,0x6A } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation>{ static constexpr guid value{ 0x53D69B5B,0xC4ED,0x45F0,{ 0x80,0x3A,0xD9,0x41,0x7A,0x6D,0x98,0x46 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails>{ static constexpr guid value{ 0x4A055B70,0xB9AE,0x4458,{ 0x92,0x41,0xA6,0xA5,0xFB,0xF1,0x8A,0x0C } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModem>{ static constexpr guid value{ 0xD0356912,0xE9F9,0x4F67,{ 0xA0,0x3D,0x43,0x18,0x9A,0x31,0x6B,0xF1 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModem2>{ static constexpr guid value{ 0x12862B28,0xB9EB,0x4EE2,{ 0xBB,0xE3,0x71,0x1F,0x53,0xEE,0xA3,0x73 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModem3>{ static constexpr guid value{ 0xE9FEC6EA,0x2F34,0x4582,{ 0x91,0x02,0xC3,0x14,0xD2,0xA8,0x7E,0xEC } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration>{ static constexpr guid value{ 0xFCE035A3,0xD6CD,0x4320,{ 0xB9,0x82,0xBE,0x9D,0x3E,0xC7,0x89,0x0F } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>{ static constexpr guid value{ 0x320FF5C5,0xE460,0x42AE,{ 0xAA,0x51,0x69,0x62,0x1E,0x7A,0x44,0x77 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation>{ static constexpr guid value{ 0xB5618FEC,0xE661,0x4330,{ 0x9B,0xB4,0x34,0x80,0x21,0x2E,0xC3,0x54 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory>{ static constexpr guid value{ 0x21D7EC58,0xC2B1,0x4C2F,{ 0xA0,0x30,0x72,0x82,0x0A,0x24,0xEC,0xD9 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>{ static constexpr guid value{ 0xF99ED637,0xD6F1,0x4A78,{ 0x8C,0xBC,0x64,0x21,0xA6,0x50,0x63,0xC8 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork>{ static constexpr guid value{ 0xCB63928C,0x0309,0x4CB6,{ 0xA8,0xC1,0x6A,0x5A,0x3C,0x8E,0x1F,0xF6 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2>{ static constexpr guid value{ 0x5A55DB22,0x62F7,0x4BDD,{ 0xBA,0x1D,0x47,0x74,0x41,0x96,0x0B,0xA0 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>{ static constexpr guid value{ 0x33670A8A,0xC7EF,0x444C,{ 0xAB,0x6C,0xDF,0x7E,0xF7,0xA3,0x90,0xFE } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange>{ static constexpr guid value{ 0xBEAF94E1,0x960F,0x49B4,{ 0xA0,0x8D,0x7D,0x85,0xE9,0x68,0xC7,0xEC } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ static constexpr guid value{ 0x89135CFF,0x28B8,0x46AA,{ 0xB1,0x37,0x1C,0x4B,0x0F,0x21,0xED,0xFE } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPco>{ static constexpr guid value{ 0xD4E4FCBE,0xE3A3,0x43C5,{ 0xA8,0x7B,0x6C,0x86,0xD2,0x29,0xD7,0xFA } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails>{ static constexpr guid value{ 0x263F5114,0x64E0,0x4493,{ 0x90,0x9B,0x2D,0x14,0xA0,0x19,0x62,0xB1 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPin>{ static constexpr guid value{ 0xE661D709,0xE779,0x45BF,{ 0x82,0x81,0x75,0x32,0x3D,0xF9,0xE3,0x21 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange>{ static constexpr guid value{ 0xBE16673E,0x1F04,0x4F95,{ 0x8B,0x90,0xE7,0xF5,0x59,0xDD,0xE7,0xE5 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails>{ static constexpr guid value{ 0xD338C091,0x3E91,0x4D38,{ 0x90,0x36,0xAE,0xE8,0x3A,0x6E,0x79,0xAD } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPinManager>{ static constexpr guid value{ 0x83567EDD,0x6E1F,0x4B9B,{ 0xA4,0x13,0x2B,0x1F,0x50,0xCC,0x36,0xDF } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult>{ static constexpr guid value{ 0x11DDDC32,0x31E7,0x49F5,{ 0xB6,0x63,0x12,0x3D,0x3B,0xEF,0x03,0x62 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange>{ static constexpr guid value{ 0xB054A561,0x9833,0x4AED,{ 0x97,0x17,0x43,0x48,0xB2,0x1A,0x24,0xB3 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails>{ static constexpr guid value{ 0x71301ACE,0x093C,0x42C6,{ 0xB0,0xDB,0xAD,0x1F,0x75,0xA6,0x54,0x45 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager>{ static constexpr guid value{ 0xE5B26833,0x967E,0x40C9,{ 0xA4,0x85,0x19,0xC0,0xDD,0x20,0x9E,0x22 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs>{ static constexpr guid value{ 0x612E3875,0x040A,0x4F99,{ 0xA4,0xF9,0x61,0xD7,0xC3,0x2D,0xA1,0x29 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandUicc>{ static constexpr guid value{ 0xE634F691,0x525A,0x4CE2,{ 0x8F,0xCE,0xAA,0x41,0x62,0x57,0x91,0x54 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp>{ static constexpr guid value{ 0x4D170556,0x98A1,0x43DD,{ 0xB2,0xEC,0x50,0xC9,0x0C,0xF2,0x48,0xDF } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult>{ static constexpr guid value{ 0x64C95285,0x358E,0x47C5,{ 0x82,0x49,0x69,0x5F,0x38,0x3B,0x2B,0xDB } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult>{ static constexpr guid value{ 0xD919682F,0xBE14,0x4934,{ 0x98,0x1D,0x2F,0x57,0xB9,0xED,0x83,0xE6 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult>{ static constexpr guid value{ 0x744930EB,0x8157,0x4A41,{ 0x84,0x94,0x6B,0xF5,0x4C,0x9B,0x1D,0x2B } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails>{ static constexpr guid value{ 0x50E3126D,0xA465,0x4EEB,{ 0x93,0x17,0x28,0xA1,0x67,0x63,0x0C,0xEA } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails>{ static constexpr guid value{ 0xBC68A9D1,0x82E1,0x4488,{ 0x9F,0x2C,0x12,0x76,0xC2,0x46,0x8F,0xAC } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration>{ static constexpr guid value{ 0x0BCC0284,0x412E,0x403D,{ 0xAC,0xC6,0xB7,0x57,0xE3,0x47,0x74,0xA4 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient>{ static constexpr guid value{ 0x709D254C,0x595F,0x4847,{ 0xBB,0x30,0x64,0x69,0x35,0x54,0x29,0x18 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>{ static constexpr guid value{ 0x91B14016,0x8DCA,0x4225,{ 0xBB,0xED,0xEE,0xF8,0xB8,0xD7,0x18,0xD7 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>{ static constexpr guid value{ 0x0108916D,0x9E9A,0x4AF6,{ 0x8D,0xA3,0x60,0x49,0x3B,0x19,0xC2,0x04 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager>{ static constexpr guid value{ 0xD45A8DA0,0x0E86,0x4D98,{ 0x8B,0xA4,0xDD,0x70,0xD4,0xB7,0x64,0xD3 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>{ static constexpr guid value{ 0x3EBCBACC,0xF8C3,0x405C,{ 0x99,0x64,0x70,0xA1,0xEE,0xAB,0xE1,0x94 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>{ static constexpr guid value{ 0x5B235412,0x35F0,0x49E7,{ 0x9B,0x08,0x16,0xD2,0x78,0xFB,0xAA,0x42 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3>{ static constexpr guid value{ 0x8FDAADB6,0x4AF9,0x4F21,{ 0x9B,0x58,0xD5,0x3E,0x9F,0x24,0x23,0x1E } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult>{ static constexpr guid value{ 0xEBD203A1,0x01BA,0x476D,{ 0xB4,0xB3,0xBF,0x3D,0x12,0xC8,0xF8,0x0C } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults>{ static constexpr guid value{ 0x217700E0,0x8203,0x11DF,{ 0xAD,0xB9,0xF4,0xCE,0x46,0x2D,0x91,0x37 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IProvisionedProfile>{ static constexpr guid value{ 0x217700E0,0x8202,0x11DF,{ 0xAD,0xB9,0xF4,0xCE,0x46,0x2D,0x91,0x37 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IProvisioningAgent>{ static constexpr guid value{ 0x217700E0,0x8201,0x11DF,{ 0xAD,0xB9,0xF4,0xCE,0x46,0x2D,0x91,0x37 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods>{ static constexpr guid value{ 0x217700E0,0x8101,0x11DF,{ 0xAD,0xB9,0xF4,0xCE,0x46,0x2D,0x91,0x37 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails>{ static constexpr guid value{ 0x03C65E9D,0x5926,0x41F3,{ 0xA9,0x4E,0xB5,0x09,0x26,0xFC,0x42,0x1B } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IUssdMessage>{ static constexpr guid value{ 0x2F9ACF82,0x2004,0x4D5D,{ 0xBF,0x81,0x2A,0xBA,0x1B,0x4B,0xE4,0xA8 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IUssdMessageFactory>{ static constexpr guid value{ 0x2F9ACF82,0x1003,0x4D5D,{ 0xBF,0x81,0x2A,0xBA,0x1B,0x4B,0xE4,0xA8 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IUssdReply>{ static constexpr guid value{ 0x2F9ACF82,0x2005,0x4D5D,{ 0xBF,0x81,0x2A,0xBA,0x1B,0x4B,0xE4,0xA8 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IUssdSession>{ static constexpr guid value{ 0x2F9ACF82,0x2002,0x4D5D,{ 0xBF,0x81,0x2A,0xBA,0x1B,0x4B,0xE4,0xA8 } }; };
template <> struct guid_storage<Windows::Networking::NetworkOperators::IUssdSessionStatics>{ static constexpr guid value{ 0x2F9ACF82,0x1001,0x4D5D,{ 0xBF,0x81,0x2A,0xBA,0x1B,0x4B,0xE4,0xA8 } }; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESim>{ using type = Windows::Networking::NetworkOperators::IESim; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimAddedEventArgs>{ using type = Windows::Networking::NetworkOperators::IESimAddedEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimDiscoverEvent>{ using type = Windows::Networking::NetworkOperators::IESimDiscoverEvent; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimDiscoverResult>{ using type = Windows::Networking::NetworkOperators::IESimDiscoverResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult>{ using type = Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimOperationResult>{ using type = Windows::Networking::NetworkOperators::IESimOperationResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimPolicy>{ using type = Windows::Networking::NetworkOperators::IESimPolicy; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimProfile>{ using type = Windows::Networking::NetworkOperators::IESimProfile; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimProfileMetadata>{ using type = Windows::Networking::NetworkOperators::IESimProfileMetadata; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimProfilePolicy>{ using type = Windows::Networking::NetworkOperators::IESimProfilePolicy; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimRemovedEventArgs>{ using type = Windows::Networking::NetworkOperators::IESimRemovedEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimServiceInfo>{ using type = Windows::Networking::NetworkOperators::IESimServiceInfo; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimUpdatedEventArgs>{ using type = Windows::Networking::NetworkOperators::IESimUpdatedEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ESimWatcher>{ using type = Windows::Networking::NetworkOperators::IESimWatcher; };
template <> struct default_interface<Windows::Networking::NetworkOperators::HotspotAuthenticationContext>{ using type = Windows::Networking::NetworkOperators::IHotspotAuthenticationContext; };
template <> struct default_interface<Windows::Networking::NetworkOperators::HotspotAuthenticationEventDetails>{ using type = Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult>{ using type = Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandAccount>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandAccount; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandCellLte; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceService>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceTriggerDetails>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandModem>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandModem; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandNetwork>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandNetwork; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPco>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPco; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPcoDataChangeTriggerDetails>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPin>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPin; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChangeTriggerDetails>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPinManager>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPinManager; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChangeTriggerDetails>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandSarManager>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandSarManager; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandUicc>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandUicc; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult>{ using type = Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::NetworkOperatorDataUsageTriggerDetails>{ using type = Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::NetworkOperatorNotificationEventDetails>{ using type = Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration>{ using type = Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration; };
template <> struct default_interface<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient>{ using type = Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient; };
template <> struct default_interface<Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager>{ using type = Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager; };
template <> struct default_interface<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>{ using type = Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults>{ using type = Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ProvisionedProfile>{ using type = Windows::Networking::NetworkOperators::IProvisionedProfile; };
template <> struct default_interface<Windows::Networking::NetworkOperators::ProvisioningAgent>{ using type = Windows::Networking::NetworkOperators::IProvisioningAgent; };
template <> struct default_interface<Windows::Networking::NetworkOperators::TetheringEntitlementCheckTriggerDetails>{ using type = Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails; };
template <> struct default_interface<Windows::Networking::NetworkOperators::UssdMessage>{ using type = Windows::Networking::NetworkOperators::IUssdMessage; };
template <> struct default_interface<Windows::Networking::NetworkOperators::UssdReply>{ using type = Windows::Networking::NetworkOperators::IUssdReply; };
template <> struct default_interface<Windows::Networking::NetworkOperators::UssdSession>{ using type = Windows::Networking::NetworkOperators::IUssdSession; };

template <> struct abi<Windows::Networking::NetworkOperators::IESim>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AvailableMemoryInBytes(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Eid(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirmwareVersion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MobileBroadbandModemDeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Policy(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Networking::NetworkOperators::ESimState* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetProfiles(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteProfileAsync(void* profileId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DownloadProfileMetadataAsync(void* activationCode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ResetAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_ProfileChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ProfileChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESim2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Discover(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DiscoverWithServerAddressAndMatchingId(void* serverAddress, void* matchingId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DiscoverAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DiscoverWithServerAddressAndMatchingIdAsync(void* serverAddress, void* matchingId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimAddedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ESim(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimDiscoverEvent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MatchingId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RspServerAddress(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimDiscoverResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Events(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::Networking::NetworkOperators::ESimDiscoverResultKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProfileMetadata(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Result(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Result(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProfileMetadata(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ServiceInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateESimWatcher(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_ServiceInfoChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ServiceInfoChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimOperationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::ESimOperationStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimPolicy>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ShouldEnableManagingUi(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimProfile>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Class(Windows::Networking::NetworkOperators::ESimProfileClass* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Nickname(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Policy(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderIcon(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Networking::NetworkOperators::ESimProfileState* value) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL EnableAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetNicknameAsync(void* newNickname, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimProfileMetadata>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsConfirmationCodeRequired(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Policy(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderIcon(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Networking::NetworkOperators::ESimProfileMetadataState* value) noexcept = 0;
    virtual int32_t WINRT_CALL DenyInstallAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ConfirmInstallAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ConfirmInstallWithConfirmationCodeAsync(void* confirmationCode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PostponeInstallAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimProfilePolicy>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanDelete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanDisable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsManagedByEnterprise(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimRemovedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ESim(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimServiceInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AuthenticationPreference(Windows::Networking::NetworkOperators::ESimAuthenticationPreference* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsESimUiEnabled(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ESim(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IESimWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::ESimWatcherStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
    virtual int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IFdnAccessManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestUnlockAsync(void* contactListId, void** returnValue) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WirelessNetworkId(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkAdapter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RedirectMessageUrl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RedirectMessageXml(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthenticationUrl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL IssueCredentials(void* userName, void* password, void* extraParameters, bool markAsManualConnectOnFailure) noexcept = 0;
    virtual int32_t WINRT_CALL AbortAuthentication(bool markAsManual) noexcept = 0;
    virtual int32_t WINRT_CALL SkipAuthentication() noexcept = 0;
    virtual int32_t WINRT_CALL TriggerAttentionRequired(void* packageRelativeApplicationId, void* applicationParameters) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IssueCredentialsAsync(void* userName, void* password, void* extraParameters, bool markAsManualConnectOnFailure, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetAuthenticationContext(void* evenToken, void** context, bool* isValid) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EventToken(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HasNetworkErrorOccurred(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseCode(Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LogoffUrl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthenticationReplyXml(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EFSpn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid2(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EFSpn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid2(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EFOns(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EFSpn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid2(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EFSpn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EFOpl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EFPnn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gid2(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccount>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceProviderGuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceProviderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentNetwork(void** network) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentDeviceInformation(void** deviceInformation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccount2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetConnectionProfiles(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AccountExperienceUrl(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AvailableNetworkAccountIds(void** ppAccountIds) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** ppAccount) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasDeviceInformationChanged(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasNetworkChanged(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_AccountAdded(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccountAdded(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccountUpdated(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccountUpdated(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccountRemoved(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccountRemoved(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Stopped(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus* status) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AntennaIndex(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SarBackoffIndex(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithIndex(int32_t antennaIndex, int32_t sarBackoffIndex, void** antennaSar) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BaseStationId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BaseStationPNCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BaseStationLatitude(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BaseStationLongitude(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BaseStationLastBroadcastGpsTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PilotSignalStrengthInDB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BaseStationId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CellId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocationAreaCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReceivedSignalStrengthInDBm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimingAdvanceInBitPeriods(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandCellLte>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CellId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalCellId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReferenceSignalReceivedPowerInDBm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReferenceSignalReceivedQualityInDBm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimingAdvanceInBitPeriods(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrackingAreaCode(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CellId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CellParameterId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocationAreaCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PathLossInDB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReceivedSignalCodePowerInDBm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimingAdvanceInBitPeriods(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CellId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocationAreaCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PathLossInDB(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrimaryScramblingCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReceivedSignalCodePowerInDBm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalToNoiseRatioInDB(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NeighboringCellsCdma(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeighboringCellsGsm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeighboringCellsLte(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeighboringCellsTdscdma(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeighboringCellsUmts(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServingCellsCdma(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServingCellsGsm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServingCellsLte(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServingCellsTdscdma(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServingCellsUmts(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkDeviceStatus(Windows::Networking::NetworkOperators::NetworkDeviceStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Manufacturer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Model(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirmwareInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataClasses(Windows::Networking::NetworkOperators::DataClasses* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomDataClass(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MobileEquipmentId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TelephoneNumbers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubscriberId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SimIccId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceType(Windows::Networking::NetworkOperators::MobileBroadbandDeviceType* pDeviceType) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentRadioState(Windows::Networking::NetworkOperators::MobileBroadbandRadioState* pCurrentState) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PinManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Revision(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SerialNumber(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SimSpn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SimPnn(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SimGid1(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceServiceId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedCommands(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenDataSession(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenCommandSession(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StatusCode(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SendQueryCommandAsync(uint32_t commandId, void* data, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL SendSetCommandAsync(uint32_t commandId, void* data, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL CloseSession() noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ReceivedData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL WriteDataAsync(void* value, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL CloseSession() noexcept = 0;
    virtual int32_t WINRT_CALL add_DataReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DataReceived(winrt::event_token eventCookie) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceServiceId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDataReadSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDataWriteSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceServiceId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReceivedData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CurrentAccount(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxDeviceServiceCommandSizeInBytes(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxDeviceServiceDataSizeInBytes(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceServices(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceService(winrt::guid deviceServiceId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsResetSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL ResetAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentConfigurationAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentNetwork(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModem2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetIsPassthroughEnabledAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL SetIsPassthroughEnabledAsync(bool value, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModem3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetPcoAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInEmergencyCallMode(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_IsInEmergencyCallModeChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_IsInEmergencyCallModeChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uicc(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HomeProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HomeProviderName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SarManager(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddAllowedHost(void* host) noexcept = 0;
    virtual int32_t WINRT_CALL AddAllowedHostRange(void* first, void* last) noexcept = 0;
    virtual int32_t WINRT_CALL ApplyConfigurationAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ClearConfigurationAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* modemDeviceId, void* ruleGroupId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromId(void* deviceId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkAdapter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkRegistrationState(Windows::Networking::NetworkOperators::NetworkRegistrationState* registrationState) noexcept = 0;
    virtual int32_t WINRT_CALL get_RegistrationNetworkError(uint32_t* networkError) noexcept = 0;
    virtual int32_t WINRT_CALL get_PacketAttachNetworkError(uint32_t* networkError) noexcept = 0;
    virtual int32_t WINRT_CALL get_ActivationNetworkError(uint32_t* networkError) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessPointName(void** apn) noexcept = 0;
    virtual int32_t WINRT_CALL get_RegisteredDataClass(Windows::Networking::NetworkOperators::DataClasses* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RegisteredProviderId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RegisteredProviderName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ShowConnectionUI() noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetVoiceCallSupportAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL get_RegistrationUiccApps(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCellsInfoAsync(void** asyncOperation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Network(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkRegistrationStateChanges(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPco>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceId(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UpdatedData(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPin>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::Networking::NetworkOperators::MobileBroadbandPinType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LockState(Windows::Networking::NetworkOperators::MobileBroadbandPinLockState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Format(Windows::Networking::NetworkOperators::MobileBroadbandPinFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Enabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxLength(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinLength(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttemptsRemaining(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL EnableAsync(void* currentPin, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL DisableAsync(void* currentPin, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL EnterAsync(void* currentPin, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL ChangeAsync(void* currentPin, void* newPin, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL UnblockAsync(void* pinUnblockKey, void* newPin, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PinType(Windows::Networking::NetworkOperators::MobileBroadbandPinType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PinLockState(Windows::Networking::NetworkOperators::MobileBroadbandPinLockState* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PinLockStateChanges(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPinManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SupportedPins(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPin(Windows::Networking::NetworkOperators::MobileBroadbandPinType pinType, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSuccessful(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttemptsRemaining(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RadioState(Windows::Networking::NetworkOperators::MobileBroadbandRadioState* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RadioStateChanges(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsBackoffEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsWiFiHardwareIntegrated(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSarControlledByHardware(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Antennas(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HysteresisTimerPeriod(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_TransmissionStateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TransmissionStateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL EnableBackoffAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DisableBackoffAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetConfigurationAsync(void* antennas, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RevertSarToHardwareControlAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetTransmissionStateChangedHysteresisAsync(Windows::Foundation::TimeSpan timerPeriod, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetIsTransmittingAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL StartTransmissionStateMonitoring() noexcept = 0;
    virtual int32_t WINRT_CALL StopTransmissionStateMonitoring() noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTransmitting(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandUicc>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SimIccId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetUiccAppsAsync(void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::Networking::NetworkOperators::UiccAppKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetRecordDetailsAsync(void* uiccFilePath, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL ReadRecordAsync(void* uiccFilePath, int32_t recordIndex, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::Networking::NetworkOperators::UiccAppRecordKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecordCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecordSize(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadAccessCondition(Windows::Networking::NetworkOperators::UiccAccessCondition* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteAccessCondition(Windows::Networking::NetworkOperators::UiccAccessCondition* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UiccApps(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NotificationKind(Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NotificationType(Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EncodingType(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RuleId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SmsMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Ssid(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Ssid(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Passphrase(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Passphrase(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MacAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HostNames(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetTetheringClients(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AuthorizeTethering(bool allow, void* entitlementFailureReason) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxClientCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ClientCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TetheringOperationalState(Windows::Networking::NetworkOperators::TetheringOperationalState* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentAccessPointConfiguration(void** configuration) noexcept = 0;
    virtual int32_t WINRT_CALL ConfigureAccessPointAsync(void* configuration, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL StartTetheringAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL StopTetheringAsync(void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetTetheringCapability(void* networkAccountId, Windows::Networking::NetworkOperators::TetheringCapability* value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** ppManager) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetTetheringCapabilityFromConnectionProfile(void* profile, Windows::Networking::NetworkOperators::TetheringCapability* result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromConnectionProfile(void* profile, void** ppManager) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromConnectionProfileWithTargetAdapter(void* profile, void* adapter, void** ppManager) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::TetheringOperationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdditionalErrorMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllElementsProvisioned(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProvisionResultsXml(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IProvisionedProfile>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL UpdateCost(Windows::Networking::Connectivity::NetworkCostType value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateUsage(struct struct_Windows_Networking_NetworkOperators_ProfileUsage value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IProvisioningAgent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ProvisionFromXmlDocumentAsync(void* provisioningXmlDocument, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL GetProvisionedProfile(Windows::Networking::NetworkOperators::ProfileMediaType mediaType, void* profileName, void** provisionedProfile) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** provisioningAgent) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL AllowTethering() noexcept = 0;
    virtual int32_t WINRT_CALL DenyTethering(void* entitlementFailureReason) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IUssdMessage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DataCodingScheme(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DataCodingScheme(uint8_t value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPayload(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPayload(uint32_t __valueSize, uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PayloadAsText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PayloadAsText(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IUssdMessageFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateMessage(void* messageText, void** ussdMessage) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IUssdReply>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResultCode(Windows::Networking::NetworkOperators::UssdResultCode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IUssdSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SendMessageAndGetReplyAsync(void* message, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL Close() noexcept = 0;
};};

template <> struct abi<Windows::Networking::NetworkOperators::IUssdSessionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** ussdSession) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNetworkInterfaceId(void* networkInterfaceId, void** ussdSession) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESim
{
    Windows::Foundation::IReference<int32_t> AvailableMemoryInBytes() const;
    hstring Eid() const;
    hstring FirmwareVersion() const;
    hstring MobileBroadbandModemDeviceId() const;
    Windows::Networking::NetworkOperators::ESimPolicy Policy() const;
    Windows::Networking::NetworkOperators::ESimState State() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimProfile> GetProfiles() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> DeleteProfileAsync(param::hstring const& profileId) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult> DownloadProfileMetadataAsync(param::hstring const& activationCode) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> ResetAsync() const;
    winrt::event_token ProfileChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESim, Windows::Foundation::IInspectable> const& handler) const;
    using ProfileChanged_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESim, &impl::abi_t<Windows::Networking::NetworkOperators::IESim>::remove_ProfileChanged>;
    ProfileChanged_revoker ProfileChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESim, Windows::Foundation::IInspectable> const& handler) const;
    void ProfileChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESim> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESim<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESim2
{
    Windows::Networking::NetworkOperators::ESimDiscoverResult Discover() const;
    Windows::Networking::NetworkOperators::ESimDiscoverResult Discover(param::hstring const& serverAddress, param::hstring const& matchingId) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult> DiscoverAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult> DiscoverAsync(param::hstring const& serverAddress, param::hstring const& matchingId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESim2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESim2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimAddedEventArgs
{
    Windows::Networking::NetworkOperators::ESim ESim() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimAddedEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimAddedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimDiscoverEvent
{
    hstring MatchingId() const;
    hstring RspServerAddress() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimDiscoverEvent> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimDiscoverEvent<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimDiscoverResult
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimDiscoverEvent> Events() const;
    Windows::Networking::NetworkOperators::ESimDiscoverResultKind Kind() const;
    Windows::Networking::NetworkOperators::ESimProfileMetadata ProfileMetadata() const;
    Windows::Networking::NetworkOperators::ESimOperationResult Result() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimDiscoverResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimDiscoverResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimDownloadProfileMetadataResult
{
    Windows::Networking::NetworkOperators::ESimOperationResult Result() const;
    Windows::Networking::NetworkOperators::ESimProfileMetadata ProfileMetadata() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimDownloadProfileMetadataResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimManagerStatics
{
    Windows::Networking::NetworkOperators::ESimServiceInfo ServiceInfo() const;
    Windows::Networking::NetworkOperators::ESimWatcher TryCreateESimWatcher() const;
    winrt::event_token ServiceInfoChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using ServiceInfoChanged_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimManagerStatics, &impl::abi_t<Windows::Networking::NetworkOperators::IESimManagerStatics>::remove_ServiceInfoChanged>;
    ServiceInfoChanged_revoker ServiceInfoChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void ServiceInfoChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimManagerStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimOperationResult
{
    Windows::Networking::NetworkOperators::ESimOperationStatus Status() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimOperationResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimOperationResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimPolicy
{
    bool ShouldEnableManagingUi() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimPolicy> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimPolicy<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimProfile
{
    Windows::Networking::NetworkOperators::ESimProfileClass Class() const;
    hstring Nickname() const;
    Windows::Networking::NetworkOperators::ESimProfilePolicy Policy() const;
    hstring Id() const;
    Windows::Storage::Streams::IRandomAccessStreamReference ProviderIcon() const;
    hstring ProviderId() const;
    hstring ProviderName() const;
    Windows::Networking::NetworkOperators::ESimProfileState State() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> DisableAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> EnableAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> SetNicknameAsync(param::hstring const& newNickname) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimProfile> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimProfile<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimProfileMetadata
{
    bool IsConfirmationCodeRequired() const;
    Windows::Networking::NetworkOperators::ESimProfilePolicy Policy() const;
    hstring Id() const;
    Windows::Storage::Streams::IRandomAccessStreamReference ProviderIcon() const;
    hstring ProviderId() const;
    hstring ProviderName() const;
    Windows::Networking::NetworkOperators::ESimProfileMetadataState State() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> DenyInstallAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress> ConfirmInstallAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress> ConfirmInstallAsync(param::hstring const& confirmationCode) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> PostponeInstallAsync() const;
    winrt::event_token StateChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimProfileMetadata, Windows::Foundation::IInspectable> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimProfileMetadata, &impl::abi_t<Windows::Networking::NetworkOperators::IESimProfileMetadata>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimProfileMetadata, Windows::Foundation::IInspectable> const& handler) const;
    void StateChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimProfileMetadata> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimProfilePolicy
{
    bool CanDelete() const;
    bool CanDisable() const;
    bool IsManagedByEnterprise() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimProfilePolicy> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimProfilePolicy<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimRemovedEventArgs
{
    Windows::Networking::NetworkOperators::ESim ESim() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimRemovedEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimRemovedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimServiceInfo
{
    Windows::Networking::NetworkOperators::ESimAuthenticationPreference AuthenticationPreference() const;
    bool IsESimUiEnabled() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimServiceInfo> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimServiceInfo<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimUpdatedEventArgs
{
    Windows::Networking::NetworkOperators::ESim ESim() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimUpdatedEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IESimWatcher
{
    Windows::Networking::NetworkOperators::ESimWatcherStatus Status() const;
    void Start() const;
    void Stop() const;
    winrt::event_token Added(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimAddedEventArgs> const& handler) const;
    using Added_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IESimWatcher>::remove_Added>;
    Added_revoker Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimAddedEventArgs> const& handler) const;
    void Added(winrt::event_token const& token) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IESimWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token Removed(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimRemovedEventArgs> const& handler) const;
    using Removed_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IESimWatcher>::remove_Removed>;
    Removed_revoker Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimRemovedEventArgs> const& handler) const;
    void Removed(winrt::event_token const& token) const noexcept;
    winrt::event_token Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using Stopped_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IESimWatcher>::remove_Stopped>;
    Stopped_revoker Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void Stopped(winrt::event_token const& token) const noexcept;
    winrt::event_token Updated(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> const& handler) const;
    using Updated_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IESimWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IESimWatcher>::remove_Updated>;
    Updated_revoker Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> const& handler) const;
    void Updated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Networking::NetworkOperators::IESimWatcher> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IESimWatcher<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IFdnAccessManagerStatics
{
    Windows::Foundation::IAsyncOperation<bool> RequestUnlockAsync(param::hstring const& contactListId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IFdnAccessManagerStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IFdnAccessManagerStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext
{
    com_array<uint8_t> WirelessNetworkId() const;
    Windows::Networking::Connectivity::NetworkAdapter NetworkAdapter() const;
    Windows::Foundation::Uri RedirectMessageUrl() const;
    Windows::Data::Xml::Dom::XmlDocument RedirectMessageXml() const;
    Windows::Foundation::Uri AuthenticationUrl() const;
    void IssueCredentials(param::hstring const& userName, param::hstring const& password, param::hstring const& extraParameters, bool markAsManualConnectOnFailure) const;
    void AbortAuthentication(bool markAsManual) const;
    void SkipAuthentication() const;
    void TriggerAttentionRequired(param::hstring const& packageRelativeApplicationId, param::hstring const& applicationParameters) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext2
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult> IssueCredentialsAsync(param::hstring const& userName, param::hstring const& password, param::hstring const& extraParameters, bool markAsManualConnectOnFailure) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContextStatics
{
    bool TryGetAuthenticationContext(param::hstring const& evenToken, Windows::Networking::NetworkOperators::HotspotAuthenticationContext& context) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContextStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationEventDetails
{
    hstring EventToken() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationEventDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IHotspotCredentialsAuthenticationResult
{
    bool HasNetworkErrorOccurred() const;
    Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode ResponseCode() const;
    Windows::Foundation::Uri LogoffUrl() const;
    Windows::Data::Xml::Dom::XmlDocument AuthenticationReplyXml() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IHotspotCredentialsAuthenticationResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IKnownCSimFilePathsStatics
{
    Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid1() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid2() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IKnownCSimFilePathsStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IKnownRuimFilePathsStatics
{
    Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid1() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid2() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IKnownRuimFilePathsStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IKnownSimFilePathsStatics
{
    Windows::Foundation::Collections::IVectorView<uint32_t> EFOns() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid1() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid2() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IKnownSimFilePathsStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics
{
    Windows::Foundation::Collections::IVectorView<uint32_t> EFSpn() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> EFOpl() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> EFPnn() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid1() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> Gid2() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount
{
    hstring NetworkAccountId() const;
    winrt::guid ServiceProviderGuid() const;
    hstring ServiceProviderName() const;
    Windows::Networking::NetworkOperators::MobileBroadbandNetwork CurrentNetwork() const;
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation CurrentDeviceInformation() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccount> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount2
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile> GetConnectionProfiles() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccount2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount3
{
    Windows::Foundation::Uri AccountExperienceUrl() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccount3> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount3<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountEventArgs
{
    hstring NetworkAccountId() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountStatics
{
    Windows::Foundation::Collections::IVectorView<hstring> AvailableNetworkAccountIds() const;
    Windows::Networking::NetworkOperators::MobileBroadbandAccount CreateFromNetworkAccountId(param::hstring const& networkAccountId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountUpdatedEventArgs
{
    hstring NetworkAccountId() const;
    bool HasDeviceInformationChanged() const;
    bool HasNetworkChanged() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher
{
    winrt::event_token AccountAdded(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const;
    using AccountAdded_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>::remove_AccountAdded>;
    AccountAdded_revoker AccountAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const;
    void AccountAdded(winrt::event_token const& cookie) const noexcept;
    winrt::event_token AccountUpdated(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> const& handler) const;
    using AccountUpdated_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>::remove_AccountUpdated>;
    AccountUpdated_revoker AccountUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> const& handler) const;
    void AccountUpdated(winrt::event_token const& cookie) const noexcept;
    winrt::event_token AccountRemoved(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const;
    using AccountRemoved_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>::remove_AccountRemoved>;
    AccountRemoved_revoker AccountRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const;
    void AccountRemoved(winrt::event_token const& cookie) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& cookie) const noexcept;
    winrt::event_token Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using Stopped_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>::remove_Stopped>;
    Stopped_revoker Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void Stopped(winrt::event_token const& cookie) const noexcept;
    Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus Status() const;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSar
{
    int32_t AntennaIndex() const;
    int32_t SarBackoffIndex() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSar<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSarFactory
{
    Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar CreateWithIndex(int32_t antennaIndex, int32_t sarBackoffIndex) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSarFactory<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma
{
    Windows::Foundation::IReference<int32_t> BaseStationId() const;
    Windows::Foundation::IReference<int32_t> BaseStationPNCode() const;
    Windows::Foundation::IReference<double> BaseStationLatitude() const;
    Windows::Foundation::IReference<double> BaseStationLongitude() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> BaseStationLastBroadcastGpsTime() const;
    Windows::Foundation::IReference<int32_t> NetworkId() const;
    Windows::Foundation::IReference<double> PilotSignalStrengthInDB() const;
    Windows::Foundation::IReference<int32_t> SystemId() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm
{
    Windows::Foundation::IReference<int32_t> BaseStationId() const;
    Windows::Foundation::IReference<int32_t> CellId() const;
    Windows::Foundation::IReference<int32_t> ChannelNumber() const;
    Windows::Foundation::IReference<int32_t> LocationAreaCode() const;
    hstring ProviderId() const;
    Windows::Foundation::IReference<double> ReceivedSignalStrengthInDBm() const;
    Windows::Foundation::IReference<int32_t> TimingAdvanceInBitPeriods() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte
{
    Windows::Foundation::IReference<int32_t> CellId() const;
    Windows::Foundation::IReference<int32_t> ChannelNumber() const;
    Windows::Foundation::IReference<int32_t> PhysicalCellId() const;
    hstring ProviderId() const;
    Windows::Foundation::IReference<double> ReferenceSignalReceivedPowerInDBm() const;
    Windows::Foundation::IReference<double> ReferenceSignalReceivedQualityInDBm() const;
    Windows::Foundation::IReference<int32_t> TimingAdvanceInBitPeriods() const;
    Windows::Foundation::IReference<int32_t> TrackingAreaCode() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandCellLte> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma
{
    Windows::Foundation::IReference<int32_t> CellId() const;
    Windows::Foundation::IReference<int32_t> CellParameterId() const;
    Windows::Foundation::IReference<int32_t> ChannelNumber() const;
    Windows::Foundation::IReference<int32_t> LocationAreaCode() const;
    Windows::Foundation::IReference<double> PathLossInDB() const;
    hstring ProviderId() const;
    Windows::Foundation::IReference<double> ReceivedSignalCodePowerInDBm() const;
    Windows::Foundation::IReference<int32_t> TimingAdvanceInBitPeriods() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts
{
    Windows::Foundation::IReference<int32_t> CellId() const;
    Windows::Foundation::IReference<int32_t> ChannelNumber() const;
    Windows::Foundation::IReference<int32_t> LocationAreaCode() const;
    Windows::Foundation::IReference<double> PathLossInDB() const;
    Windows::Foundation::IReference<int32_t> PrimaryScramblingCode() const;
    hstring ProviderId() const;
    Windows::Foundation::IReference<double> ReceivedSignalCodePowerInDBm() const;
    Windows::Foundation::IReference<double> SignalToNoiseRatioInDB() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> NeighboringCellsCdma() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> NeighboringCellsGsm() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte> NeighboringCellsLte() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> NeighboringCellsTdscdma() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> NeighboringCellsUmts() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> ServingCellsCdma() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> ServingCellsGsm() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte> ServingCellsLte() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> ServingCellsTdscdma() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> ServingCellsUmts() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation
{
    Windows::Networking::NetworkOperators::NetworkDeviceStatus NetworkDeviceStatus() const;
    hstring Manufacturer() const;
    hstring Model() const;
    hstring FirmwareInformation() const;
    Windows::Devices::Sms::CellularClass CellularClass() const;
    Windows::Networking::NetworkOperators::DataClasses DataClasses() const;
    hstring CustomDataClass() const;
    hstring MobileEquipmentId() const;
    Windows::Foundation::Collections::IVectorView<hstring> TelephoneNumbers() const;
    hstring SubscriberId() const;
    hstring SimIccId() const;
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceType DeviceType() const;
    hstring DeviceId() const;
    Windows::Networking::NetworkOperators::MobileBroadbandRadioState CurrentRadioState() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation2
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinManager PinManager() const;
    hstring Revision() const;
    hstring SerialNumber() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation3
{
    hstring SimSpn() const;
    hstring SimPnn() const;
    hstring SimGid1() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation3<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceService
{
    winrt::guid DeviceServiceId() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> SupportedCommands() const;
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession OpenDataSession() const;
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession OpenCommandSession() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceService<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandResult
{
    uint32_t StatusCode() const;
    Windows::Storage::Streams::IBuffer ResponseData() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandSession
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> SendQueryCommandAsync(uint32_t commandId, Windows::Storage::Streams::IBuffer const& data) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> SendSetCommandAsync(uint32_t commandId, Windows::Storage::Streams::IBuffer const& data) const;
    void CloseSession() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandSession<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataReceivedEventArgs
{
    Windows::Storage::Streams::IBuffer ReceivedData() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession
{
    Windows::Foundation::IAsyncAction WriteDataAsync(Windows::Storage::Streams::IBuffer const& value) const;
    void CloseSession() const;
    winrt::event_token DataReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession, Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> const& eventHandler) const;
    using DataReceived_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession>::remove_DataReceived>;
    DataReceived_revoker DataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession, Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> const& eventHandler) const;
    void DataReceived(winrt::event_token const& eventCookie) const noexcept;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceInformation
{
    winrt::guid DeviceServiceId() const;
    bool IsDataReadSupported() const;
    bool IsDataWriteSupported() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceInformation<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceTriggerDetails
{
    hstring DeviceId() const;
    winrt::guid DeviceServiceId() const;
    Windows::Storage::Streams::IBuffer ReceivedData() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem
{
    Windows::Networking::NetworkOperators::MobileBroadbandAccount CurrentAccount() const;
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation DeviceInformation() const;
    uint32_t MaxDeviceServiceCommandSizeInBytes() const;
    uint32_t MaxDeviceServiceDataSizeInBytes() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation> DeviceServices() const;
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceService GetDeviceService(winrt::guid const& deviceServiceId) const;
    bool IsResetSupported() const;
    Windows::Foundation::IAsyncAction ResetAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration> GetCurrentConfigurationAsync() const;
    Windows::Networking::NetworkOperators::MobileBroadbandNetwork CurrentNetwork() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModem> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem2
{
    Windows::Foundation::IAsyncOperation<bool> GetIsPassthroughEnabledAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus> SetIsPassthroughEnabledAsync(bool value) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModem2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPco> TryGetPcoAsync() const;
    bool IsInEmergencyCallMode() const;
    winrt::event_token IsInEmergencyCallModeChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandModem, Windows::Foundation::IInspectable> const& handler) const;
    using IsInEmergencyCallModeChanged_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandModem3, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandModem3>::remove_IsInEmergencyCallModeChanged>;
    IsInEmergencyCallModeChanged_revoker IsInEmergencyCallModeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandModem, Windows::Foundation::IInspectable> const& handler) const;
    void IsInEmergencyCallModeChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModem3> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration
{
    Windows::Networking::NetworkOperators::MobileBroadbandUicc Uicc() const;
    hstring HomeProviderId() const;
    hstring HomeProviderName() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration2
{
    Windows::Networking::NetworkOperators::MobileBroadbandSarManager SarManager() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolation
{
    void AddAllowedHost(Windows::Networking::HostName const& host) const;
    void AddAllowedHostRange(Windows::Networking::HostName const& first, Windows::Networking::HostName const& last) const;
    Windows::Foundation::IAsyncAction ApplyConfigurationAsync() const;
    Windows::Foundation::IAsyncAction ClearConfigurationAsync() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolation<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolationFactory
{
    Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation Create(param::hstring const& modemDeviceId, param::hstring const& ruleGroupId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolationFactory<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemStatics
{
    hstring GetDeviceSelector() const;
    Windows::Networking::NetworkOperators::MobileBroadbandModem FromId(param::hstring const& deviceId) const;
    Windows::Networking::NetworkOperators::MobileBroadbandModem GetDefault() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork
{
    Windows::Networking::Connectivity::NetworkAdapter NetworkAdapter() const;
    Windows::Networking::NetworkOperators::NetworkRegistrationState NetworkRegistrationState() const;
    uint32_t RegistrationNetworkError() const;
    uint32_t PacketAttachNetworkError() const;
    uint32_t ActivationNetworkError() const;
    hstring AccessPointName() const;
    Windows::Networking::NetworkOperators::DataClasses RegisteredDataClass() const;
    hstring RegisteredProviderId() const;
    hstring RegisteredProviderName() const;
    void ShowConnectionUI() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork2
{
    Windows::Foundation::IAsyncOperation<bool> GetVoiceCallSupportAsync() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> RegistrationUiccApps() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork3
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo> GetCellsInfoAsync() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork3<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChange
{
    hstring DeviceId() const;
    Windows::Networking::NetworkOperators::MobileBroadbandNetwork Network() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChange<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange> NetworkRegistrationStateChanges() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPco
{
    Windows::Storage::Streams::IBuffer Data() const;
    bool IsComplete() const;
    hstring DeviceId() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPco> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPco<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPcoDataChangeTriggerDetails
{
    Windows::Networking::NetworkOperators::MobileBroadbandPco UpdatedData() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPcoDataChangeTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinType Type() const;
    Windows::Networking::NetworkOperators::MobileBroadbandPinLockState LockState() const;
    Windows::Networking::NetworkOperators::MobileBroadbandPinFormat Format() const;
    bool Enabled() const;
    uint32_t MaxLength() const;
    uint32_t MinLength() const;
    uint32_t AttemptsRemaining() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> EnableAsync(param::hstring const& currentPin) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> DisableAsync(param::hstring const& currentPin) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> EnterAsync(param::hstring const& currentPin) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> ChangeAsync(param::hstring const& currentPin, param::hstring const& newPin) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> UnblockAsync(param::hstring const& pinUnblockKey, param::hstring const& newPin) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPin> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChange
{
    hstring DeviceId() const;
    Windows::Networking::NetworkOperators::MobileBroadbandPinType PinType() const;
    Windows::Networking::NetworkOperators::MobileBroadbandPinLockState PinLockState() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChange<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChangeTriggerDetails
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange> PinLockStateChanges() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChangeTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinManager
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinType> SupportedPins() const;
    Windows::Networking::NetworkOperators::MobileBroadbandPin GetPin(Windows::Networking::NetworkOperators::MobileBroadbandPinType const& pinType) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPinManager> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinManager<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinOperationResult
{
    bool IsSuccessful() const;
    uint32_t AttemptsRemaining() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinOperationResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChange
{
    hstring DeviceId() const;
    Windows::Networking::NetworkOperators::MobileBroadbandRadioState RadioState() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChange<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChangeTriggerDetails
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange> RadioStateChanges() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChangeTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager
{
    bool IsBackoffEnabled() const;
    bool IsWiFiHardwareIntegrated() const;
    bool IsSarControlledByHardware() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> Antennas() const;
    Windows::Foundation::TimeSpan HysteresisTimerPeriod() const;
    winrt::event_token TransmissionStateChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandSarManager, Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> const& handler) const;
    using TransmissionStateChanged_revoker = impl::event_revoker<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager, &impl::abi_t<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager>::remove_TransmissionStateChanged>;
    TransmissionStateChanged_revoker TransmissionStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandSarManager, Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> const& handler) const;
    void TransmissionStateChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncAction EnableBackoffAsync() const;
    Windows::Foundation::IAsyncAction DisableBackoffAsync() const;
    Windows::Foundation::IAsyncAction SetConfigurationAsync(param::async_iterable<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> const& antennas) const;
    Windows::Foundation::IAsyncAction RevertSarToHardwareControlAsync() const;
    Windows::Foundation::IAsyncAction SetTransmissionStateChangedHysteresisAsync(Windows::Foundation::TimeSpan const& timerPeriod) const;
    Windows::Foundation::IAsyncOperation<bool> GetIsTransmittingAsync() const;
    void StartTransmissionStateMonitoring() const;
    void StopTransmissionStateMonitoring() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandSarManager> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandTransmissionStateChangedEventArgs
{
    bool IsTransmitting() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandTransmissionStateChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandUicc
{
    hstring SimIccId() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult> GetUiccAppsAsync() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandUicc> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandUicc<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccApp
{
    Windows::Storage::Streams::IBuffer Id() const;
    Windows::Networking::NetworkOperators::UiccAppKind Kind() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult> GetRecordDetailsAsync(param::async_iterable<uint32_t> const& uiccFilePath) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult> ReadRecordAsync(param::async_iterable<uint32_t> const& uiccFilePath, int32_t recordIndex) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccApp<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppReadRecordResult
{
    Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus Status() const;
    Windows::Storage::Streams::IBuffer Data() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppReadRecordResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult
{
    Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus Status() const;
    Windows::Networking::NetworkOperators::UiccAppRecordKind Kind() const;
    int32_t RecordCount() const;
    int32_t RecordSize() const;
    Windows::Networking::NetworkOperators::UiccAccessCondition ReadAccessCondition() const;
    Windows::Networking::NetworkOperators::UiccAccessCondition WriteAccessCondition() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppsResult
{
    Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus Status() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> UiccApps() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppsResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorDataUsageTriggerDetails
{
    Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind NotificationKind() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorDataUsageTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails
{
    Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType NotificationType() const;
    hstring NetworkAccountId() const;
    uint8_t EncodingType() const;
    hstring Message() const;
    hstring RuleId() const;
    Windows::Devices::Sms::ISmsMessage SmsMessage() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringAccessPointConfiguration
{
    hstring Ssid() const;
    void Ssid(param::hstring const& value) const;
    hstring Passphrase() const;
    void Passphrase(param::hstring const& value) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringAccessPointConfiguration<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClient
{
    hstring MacAddress() const;
    Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> HostNames() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClient<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClientManager
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient> GetTetheringClients() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClientManager<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringEntitlementCheck
{
    void AuthorizeTethering(bool allow, param::hstring const& entitlementFailureReason) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringEntitlementCheck<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager
{
    uint32_t MaxClientCount() const;
    uint32_t ClientCount() const;
    Windows::Networking::NetworkOperators::TetheringOperationalState TetheringOperationalState() const;
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration GetCurrentAccessPointConfiguration() const;
    Windows::Foundation::IAsyncAction ConfigureAccessPointAsync(Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration const& configuration) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> StartTetheringAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> StopTetheringAsync() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics
{
    Windows::Networking::NetworkOperators::TetheringCapability GetTetheringCapability(param::hstring const& networkAccountId) const;
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager CreateFromNetworkAccountId(param::hstring const& networkAccountId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics2
{
    Windows::Networking::NetworkOperators::TetheringCapability GetTetheringCapabilityFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile) const;
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics2<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics3
{
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics3<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringOperationResult
{
    Windows::Networking::NetworkOperators::TetheringOperationStatus Status() const;
    hstring AdditionalErrorMessage() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringOperationResult<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IProvisionFromXmlDocumentResults
{
    bool AllElementsProvisioned() const;
    hstring ProvisionResultsXml() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IProvisionFromXmlDocumentResults<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IProvisionedProfile
{
    void UpdateCost(Windows::Networking::Connectivity::NetworkCostType const& value) const;
    void UpdateUsage(Windows::Networking::NetworkOperators::ProfileUsage const& value) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IProvisionedProfile> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IProvisionedProfile<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IProvisioningAgent
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults> ProvisionFromXmlDocumentAsync(param::hstring const& provisioningXmlDocument) const;
    Windows::Networking::NetworkOperators::ProvisionedProfile GetProvisionedProfile(Windows::Networking::NetworkOperators::ProfileMediaType const& mediaType, param::hstring const& profileName) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IProvisioningAgent> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IProvisioningAgent<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IProvisioningAgentStaticMethods
{
    Windows::Networking::NetworkOperators::ProvisioningAgent CreateFromNetworkAccountId(param::hstring const& networkAccountId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IProvisioningAgentStaticMethods<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_ITetheringEntitlementCheckTriggerDetails
{
    hstring NetworkAccountId() const;
    void AllowTethering() const;
    void DenyTethering(param::hstring const& entitlementFailureReason) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_ITetheringEntitlementCheckTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IUssdMessage
{
    uint8_t DataCodingScheme() const;
    void DataCodingScheme(uint8_t value) const;
    com_array<uint8_t> GetPayload() const;
    void SetPayload(array_view<uint8_t const> value) const;
    hstring PayloadAsText() const;
    void PayloadAsText(param::hstring const& value) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IUssdMessage> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IUssdMessage<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IUssdMessageFactory
{
    Windows::Networking::NetworkOperators::UssdMessage CreateMessage(param::hstring const& messageText) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IUssdMessageFactory> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IUssdMessageFactory<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IUssdReply
{
    Windows::Networking::NetworkOperators::UssdResultCode ResultCode() const;
    Windows::Networking::NetworkOperators::UssdMessage Message() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IUssdReply> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IUssdReply<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IUssdSession
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::UssdReply> SendMessageAndGetReplyAsync(Windows::Networking::NetworkOperators::UssdMessage const& message) const;
    void Close() const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IUssdSession> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IUssdSession<D>; };

template <typename D>
struct consume_Windows_Networking_NetworkOperators_IUssdSessionStatics
{
    Windows::Networking::NetworkOperators::UssdSession CreateFromNetworkAccountId(param::hstring const& networkAccountId) const;
    Windows::Networking::NetworkOperators::UssdSession CreateFromNetworkInterfaceId(param::hstring const& networkInterfaceId) const;
};
template <> struct consume<Windows::Networking::NetworkOperators::IUssdSessionStatics> { template <typename D> using type = consume_Windows_Networking_NetworkOperators_IUssdSessionStatics<D>; };

struct struct_Windows_Networking_NetworkOperators_ESimProfileInstallProgress
{
    int32_t TotalSizeInBytes;
    int32_t InstalledSizeInBytes;
};
template <> struct abi<Windows::Networking::NetworkOperators::ESimProfileInstallProgress>{ using type = struct_Windows_Networking_NetworkOperators_ESimProfileInstallProgress; };


struct struct_Windows_Networking_NetworkOperators_ProfileUsage
{
    uint32_t UsageInMegabytes;
    Windows::Foundation::DateTime LastSyncTime;
};
template <> struct abi<Windows::Networking::NetworkOperators::ProfileUsage>{ using type = struct_Windows_Networking_NetworkOperators_ProfileUsage; };


}
