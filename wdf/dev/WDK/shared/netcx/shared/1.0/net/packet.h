// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#pragma region Desktop Family or OneCore Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)

#ifndef NETCX_ADAPTER_2
#error include netadaptercx.h
#endif

#pragma warning(push)
#pragma warning(default:4820) // warn if the compiler inserted padding
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int

EXTERN_C_START

typedef enum _NET_PACKET_LAYER2_TYPE
{
    NET_PACKET_LAYER2_TYPE_UNSPECIFIED                  = 0,
    NET_PACKET_LAYER2_TYPE_NULL                         = 1,
    NET_PACKET_LAYER2_TYPE_ETHERNET                     = 2,
} NET_PACKET_LAYER2_TYPE;

typedef enum _NET_PACKET_LAYER3_TYPE
{
    NET_PACKET_LAYER3_TYPE_UNSPECIFIED                  = 0,
    NET_PACKET_LAYER3_TYPE_IPV4_UNSPECIFIED_OPTIONS     = 1,
    NET_PACKET_LAYER3_TYPE_IPV4_WITH_OPTIONS            = 2,
    NET_PACKET_LAYER3_TYPE_IPV4_NO_OPTIONS              = 3,
    NET_PACKET_LAYER3_TYPE_IPV6_UNSPECIFIED_EXTENSIONS  = 4,
    NET_PACKET_LAYER3_TYPE_IPV6_WITH_EXTENSIONS         = 5,
    NET_PACKET_LAYER3_TYPE_IPV6_NO_EXTENSIONS           = 6,
} NET_PACKET_LAYER3_TYPE;

typedef enum _NET_PACKET_LAYER4_TYPE
{
    NET_PACKET_LAYER4_TYPE_UNSPECIFIED                  = 0,
    NET_PACKET_LAYER4_TYPE_TCP                          = 1,
    NET_PACKET_LAYER4_TYPE_UDP                          = 2,
    NET_PACKET_LAYER4_TYPE_IP_NOT_FRAGMENTED            = 3,
    NET_PACKET_LAYER4_TYPE_IP_FRAGMENT                  = 4,
} NET_PACKET_LAYER4_TYPE;

#include <pshpack1.h>
typedef struct _NET_PACKET_LAYOUT
{
    UINT16
        Layer2HeaderLength : 7;

    UINT16
        Layer3HeaderLength : 9;

    UINT8
        Layer4HeaderLength : 8;

    /// One of the NET_PACKET_LAYER2_TYPE values
    UINT8
        Layer2Type : 4;

    /// One of the NET_PACKET_LAYER3_TYPE values
    UINT8
        Layer3Type : 4;

    /// One of the NET_PACKET_LAYER4_TYPE values
    UINT8
        Layer4Type : 4;

    UINT8
        Reserved0 : 4;

} NET_PACKET_LAYOUT;
#include <poppack.h>

C_ASSERT(sizeof(NET_PACKET_LAYOUT) == 5);

#define NET_PACKET_ALIGNMENT_BYTES 16

typedef struct DECLSPEC_ALIGN(NET_PACKET_ALIGNMENT_BYTES) _NET_PACKET
{
    UINT32
        FragmentIndex;

    UINT32
        Reserved0;

    UINT16
        FragmentCount;

    NET_PACKET_LAYOUT
        Layout;

    UINT8
        Ignore : 1;

    UINT8
        Scratch : 1;

    UINT8
        Reserved1 : 6;

} NET_PACKET;

C_ASSERT(sizeof(NET_PACKET) == 16);

#pragma warning(pop)

inline
BOOLEAN
NetPacketIsIpv4(
    const NET_PACKET * packet
)
{
    return (packet->Layout.Layer3Type == NET_PACKET_LAYER3_TYPE_IPV4_NO_OPTIONS ||
        packet->Layout.Layer3Type == NET_PACKET_LAYER3_TYPE_IPV4_UNSPECIFIED_OPTIONS ||
        packet->Layout.Layer3Type == NET_PACKET_LAYER3_TYPE_IPV4_WITH_OPTIONS);
}

inline
BOOLEAN
NetPacketIsIpv6(
    const NET_PACKET * packet
)
{
    return (packet->Layout.Layer3Type == NET_PACKET_LAYER3_TYPE_IPV6_NO_EXTENSIONS ||
        packet->Layout.Layer3Type == NET_PACKET_LAYER3_TYPE_IPV6_UNSPECIFIED_EXTENSIONS ||
        packet->Layout.Layer3Type == NET_PACKET_LAYER3_TYPE_IPV6_WITH_EXTENSIONS);
}

inline
void *
NetPacketGetExtension(
    const NET_PACKET * packet,
    SIZE_T offset
)
{
    NT_ASSERT(offset <= 0xffff);

    return (void *)((UCHAR*)(packet)+offset);
}

EXTERN_C_END

#endif // WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)
#pragma endregion

