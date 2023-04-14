// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#pragma region Desktop Family or OneCore Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)


#include <net/lsotypes.h>

EXTERN_C_START

inline
NET_PACKET_LARGE_SEND_SEGMENTATION *
NetExtensionGetPacketLargeSendSegmentation(
    NET_EXTENSION const * Extension,
    UINT32 Index
)
{
    return (NET_PACKET_LARGE_SEND_SEGMENTATION *)NetExtensionGetData(Extension, Index);
}

EXTERN_C_END

#endif // WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)
#pragma endregion

