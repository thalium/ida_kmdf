// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#pragma region Desktop Family or OneCore Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)

EXTERN_C_START

#pragma warning(push)
#pragma warning(default:4820) // warn if the compiler inserted padding
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union

typedef struct _NET_PACKET_RECEIVE_SEGMENT_COALESCENCE
{
    UINT16
        CoalescedSegmentCount;

    union {
        struct {
            UINT16
                RscTcpTimestampDelta;
        } TCP;
    } DUMMYUNIONNAME;
} NET_PACKET_RECEIVE_SEGMENT_COALESCENCE;

C_ASSERT(sizeof(NET_PACKET_RECEIVE_SEGMENT_COALESCENCE) == 8);

#pragma warning(pop)

EXTERN_C_END


#define NET_PACKET_EXTENSION_RSC_NAME L"ms_packetreceivesegmentcoalescence"
#define NET_PACKET_EXTENSION_RSC_VERSION_1 1
#define NET_PACKET_EXTENSION_RSC_VERSION_1_SIZE sizeof(NET_PACKET_RECEIVE_SEGMENT_COALESCENCE)

#endif // WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)
#pragma endregion

