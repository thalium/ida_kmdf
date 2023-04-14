/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

_WdfVersionBuild_

Module Name: NetFuncEnum.h

Abstract:
    Generated an enum of all WDF API functions

Environment:
    kernel mode only

    Warning: manual changes to this file will be lost.
--*/

#ifndef _NETFUNCENUM_1_4_H_
#define _NETFUNCENUM_1_4_H_

extern PNET_DRIVER_GLOBALS NetDriverGlobals;

typedef enum _NETFUNCENUM {

    NetAdapterInitAllocateTableIndex = 0,
    NetAdapterInitFreeTableIndex = 1,
    NetAdapterInitSetDatapathCallbacksTableIndex = 2,
    NetAdapterInitSetNetRequestAttributesTableIndex = 3,
    NetAdapterInitSetNetPowerSettingsAttributesTableIndex = 4,
    NetAdapterDeviceInitConfigTableIndex = 5,
    NetAdapterCreateTableIndex = 6,
    NetAdapterStartTableIndex = 7,
    NetAdapterStopTableIndex = 8,
    NetAdapterSetLinkLayerCapabilitiesTableIndex = 9,
    NetAdapterSetLinkLayerMtuSizeTableIndex = 10,
    NetAdapterSetPowerCapabilitiesTableIndex = 11,
    NetAdapterSetDataPathCapabilitiesTableIndex = 12,
    NetAdapterSetLinkStateTableIndex = 13,
    NetAdapterGetNetLuidTableIndex = 14,
    NetAdapterOpenConfigurationTableIndex = 15,
    NetAdapterGetPowerSettingsTableIndex = 16,
    NetAdapterSetPermanentLinkLayerAddressTableIndex = 17,
    NetAdapterSetCurrentLinkLayerAddressTableIndex = 18,
    NetAdapterOffloadSetChecksumCapabilitiesTableIndex = 19,
    NetOffloadIsChecksumIPv4EnabledTableIndex = 20,
    NetOffloadIsChecksumTcpEnabledTableIndex = 21,
    NetOffloadIsChecksumUdpEnabledTableIndex = 22,
    NetAdapterInitGetCreatedAdapterTableIndex = 23,
    NetAdapterExtensionInitAllocateTableIndex = 24,
    NetAdapterExtensionInitSetNetRequestPreprocessCallbackTableIndex = 25,
    NetAdapterDispatchPreprocessedNetRequestTableIndex = 26,
    NetAdapterGetParentTableIndex = 27,
    NetAdapterGetLinkLayerMtuSizeTableIndex = 28,
    NetAdapterWdmGetNdisHandleTableIndex = 29,
    NetAdapterDriverWdmGetHandleTableIndex = 30,
    NetConfigurationCloseTableIndex = 31,
    NetConfigurationOpenSubConfigurationTableIndex = 32,
    NetConfigurationQueryUlongTableIndex = 33,
    NetConfigurationQueryStringTableIndex = 34,
    NetConfigurationQueryMultiStringTableIndex = 35,
    NetConfigurationQueryBinaryTableIndex = 36,
    NetConfigurationQueryLinkLayerAddressTableIndex = 37,
    NetConfigurationAssignUlongTableIndex = 38,
    NetConfigurationAssignUnicodeStringTableIndex = 39,
    NetConfigurationAssignMultiStringTableIndex = 40,
    NetConfigurationAssignBinaryTableIndex = 41,
    NetDeviceOpenConfigurationTableIndex = 42,
    NetDeviceSetResetConfigTableIndex = 43,
    NetDeviceAssignSupportedOidListTableIndex = 44,
    NetAdapterRegisterPacketExtensionTableIndex = 45,
    NetAdapterQueryRegisteredPacketExtensionTableIndex = 46,
    NetTxQueueInitAddPacketExtensionTableIndex = 47,
    NetRxQueueInitAddPacketExtensionTableIndex = 48,
    NetPowerSettingsGetWakePatternCountTableIndex = 49,
    NetPowerSettingsGetWakePatternTableIndex = 50,
    NetPowerSettingsIsWakePatternEnabledTableIndex = 51,
    NetPowerSettingsGetEnabledWakeUpFlagsTableIndex = 52,
    NetPowerSettingsGetEnabledWakePatternFlagsTableIndex = 53,
    NetPowerSettingsGetEnabledProtocolOffloadFlagsTableIndex = 54,
    NetPowerSettingsGetEnabledMediaSpecificWakeUpEventsTableIndex = 55,
    NetPowerSettingsGetProtocolOffloadCountTableIndex = 56,
    NetPowerSettingsGetProtocolOffloadTableIndex = 57,
    NetPowerSettingsIsProtocolOffloadEnabledTableIndex = 58,
    NetAdapterSetReceiveScalingCapabilitiesTableIndex = 59,
    NetRequestRetrieveInputOutputBufferTableIndex = 60,
    NetRequestWdmGetNdisOidRequestTableIndex = 61,
    NetRequestCompleteWithoutInformationTableIndex = 62,
    NetRequestSetDataCompleteTableIndex = 63,
    NetRequestQueryDataCompleteTableIndex = 64,
    NetRequestMethodCompleteTableIndex = 65,
    NetRequestSetBytesNeededTableIndex = 66,
    NetRequestGetIdTableIndex = 67,
    NetRequestGetPortNumberTableIndex = 68,
    NetRequestGetSwitchIdTableIndex = 69,
    NetRequestGetVPortIdTableIndex = 70,
    NetRequestGetTypeTableIndex = 71,
    NetRequestGetAdapterTableIndex = 72,
    NetRequestQueueCreateTableIndex = 73,
    NetRequestQueueGetAdapterTableIndex = 74,
    NetRxQueueCreateTableIndex = 75,
    NetRxQueueNotifyMoreReceivedPacketsAvailableTableIndex = 76,
    NetRxQueueInitGetQueueIdTableIndex = 77,
    NetRxQueueGetRingCollectionTableIndex = 78,
    NetRxQueueGetExtensionTableIndex = 79,
    NetTxQueueCreateTableIndex = 80,
    NetTxQueueNotifyMoreCompletedPacketsAvailableTableIndex = 81,
    NetTxQueueInitGetQueueIdTableIndex = 82,
    NetTxQueueGetRingCollectionTableIndex = 83,
    NetTxQueueGetExtensionTableIndex = 84,
    NetFunctionTableNumEntries = 85,
} NETFUNCENUM;

#endif // _NETFUNCENUM_1_4_H_

