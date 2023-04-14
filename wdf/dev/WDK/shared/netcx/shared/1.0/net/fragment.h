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

#if _WIN64
#define NET_FRAGMENT_ALIGNMENT_BYTES 32
#else
#define NET_FRAGMENT_ALIGNMENT_BYTES 8
#endif

EXTERN_C_START

typedef UINT64 LOGICAL_ADDRESS;

typedef struct DECLSPEC_ALIGN(NET_FRAGMENT_ALIGNMENT_BYTES) _NET_FRAGMENT
{
    UINT64
        ValidLength : 26;

    UINT64
        Capacity : 26;

    UINT64
        Offset : 10;

    UINT64
        Scratch : 1;

    UINT64
        Reserved0 : 1;

    ULONG_PTR
        OsReserved_Bounced : 1;

#ifdef _WIN64
    ULONG_PTR
        Reserved : 63;
#else
    ULONG_PTR
        Reserved : 31;
#endif

    void *
        VirtualAddress;

    union
    {
        struct
        {

            void *
                RxBufferReturnContext;

        } DUMMYSTRUCTNAME;

        union
        {

            MDL *
                Mdl;

            LOGICAL_ADDRESS
                DmaLogicalAddress;

        } Mapping;
    } DUMMYUNIONNAME;

} NET_FRAGMENT;

EXTERN_C_END

#ifdef _WIN64
C_ASSERT(sizeof(NET_FRAGMENT) == 32);
#else
C_ASSERT(sizeof(NET_FRAGMENT) == 24);
#endif

#pragma warning(pop)

#endif // WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)
#pragma endregion

