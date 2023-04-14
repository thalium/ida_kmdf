/* Header file automatically generated from windows.security.dataprotection.idl */
/*
 * File built with Microsoft(R) MIDLRT Compiler Engine Version 10.00.0226 
 */

#pragma warning( disable: 4049 )  /* more than 64k source lines */

/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

/* verify that the <rpcsal.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCSAL_H_VERSION__
#define __REQUIRED_RPCSAL_H_VERSION__ 100
#endif

#include <rpc.h>
#include <rpcndr.h>

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#ifndef COM_NO_WINDOWS_H
#include <windows.h>
#include <ole2.h>
#endif /*COM_NO_WINDOWS_H*/
#ifndef __windows2Esecurity2Edataprotection_h__
#define __windows2Esecurity2Edataprotection_h__
#ifndef __windows2Esecurity2Edataprotection_p_h__
#define __windows2Esecurity2Edataprotection_p_h__


#pragma once

//
// Deprecated attribute support
//

#pragma push_macro("DEPRECATED")
#undef DEPRECATED

#if !defined(DISABLE_WINRT_DEPRECATION)
#if defined(__cplusplus)
#if __cplusplus >= 201402
#define DEPRECATED(x) [[deprecated(x)]]
#define DEPRECATEDENUMERATOR(x) [[deprecated(x)]]
#elif defined(_MSC_VER)
#if _MSC_VER >= 1900
#define DEPRECATED(x) [[deprecated(x)]]
#define DEPRECATEDENUMERATOR(x) [[deprecated(x)]]
#else
#define DEPRECATED(x) __declspec(deprecated(x))
#define DEPRECATEDENUMERATOR(x)
#endif // _MSC_VER >= 1900
#else // Not Standard C++ or MSVC, ignore the construct.
#define DEPRECATED(x)
#define DEPRECATEDENUMERATOR(x)
#endif  // C++ deprecation
#else // C - disable deprecation
#define DEPRECATED(x)
#define DEPRECATEDENUMERATOR(x)
#endif
#else // Deprecation is disabled
#define DEPRECATED(x)
#define DEPRECATEDENUMERATOR(x)
#endif  /* DEPRECATED */

// Disable Deprecation for this header, MIDL verifies that cross-type access is acceptable
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#else
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

// Ensure that the setting of the /ns_prefix command line switch is consistent for all headers.
// If you get an error from the compiler indicating "warning C4005: 'CHECK_NS_PREFIX_STATE': macro redefinition", this
// indicates that you have included two different headers with different settings for the /ns_prefix MIDL command line switch
#if !defined(DISABLE_NS_PREFIX_CHECKS)
#define CHECK_NS_PREFIX_STATE "always"
#endif // !defined(DISABLE_NS_PREFIX_CHECKS)


#pragma push_macro("MIDL_CONST_ID")
#undef MIDL_CONST_ID
#define MIDL_CONST_ID const __declspec(selectany)


//  API Contract Inclusion Definitions
#if !defined(SPECIFIC_API_CONTRACT_DEFINITIONS)
#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATEDEVENTSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATEDEVENTSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATEDEVENTSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATIONCAMERASETTINGSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATIONCAMERASETTINGSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_ACTIVATIONCAMERASETTINGSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_CONTACTACTIVATEDEVENTSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_CONTACTACTIVATEDEVENTSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_CONTACTACTIVATEDEVENTSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_WEBUISEARCHACTIVATEDEVENTSCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_ACTIVATION_WEBUISEARCHACTIVATEDEVENTSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_ACTIVATION_WEBUISEARCHACTIVATEDEVENTSCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_BACKGROUND_BACKGROUNDALARMAPPLICATIONCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_BACKGROUND_BACKGROUNDALARMAPPLICATIONCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_BACKGROUND_BACKGROUNDALARMAPPLICATIONCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_BACKGROUND_CALLSBACKGROUNDCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_BACKGROUND_CALLSBACKGROUNDCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_BACKGROUND_CALLSBACKGROUNDCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION 0x50000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION 0x40000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_COMMUNICATIONBLOCKING_COMMUNICATIONBLOCKINGCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_COMMUNICATIONBLOCKING_COMMUNICATIONBLOCKINGCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_APPLICATIONMODEL_COMMUNICATIONBLOCKING_COMMUNICATIONBLOCKINGCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_FULLTRUSTAPPCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_FULLTRUSTAPPCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_FULLTRUSTAPPCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_SEARCH_SEARCHCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_SEARCH_SEARCHCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_SEARCH_SEARCHCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_STARTUPTASKCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_STARTUPTASKCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_APPLICATIONMODEL_STARTUPTASKCONTRACT_VERSION)

#if !defined(WINDOWS_APPLICATIONMODEL_WALLET_WALLETCONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_WALLET_WALLETCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_APPLICATIONMODEL_WALLET_WALLETCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_PRINTERS_EXTENSIONS_EXTENSIONSCONTRACT_VERSION)
#define WINDOWS_DEVICES_PRINTERS_EXTENSIONS_EXTENSIONSCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_DEVICES_PRINTERS_EXTENSIONS_EXTENSIONSCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDBACKGROUNDTRIGGERCONTRACT_VERSION)
#define WINDOWS_DEVICES_SMARTCARDS_SMARTCARDBACKGROUNDTRIGGERCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDBACKGROUNDTRIGGERCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDEMULATORCONTRACT_VERSION)
#define WINDOWS_DEVICES_SMARTCARDS_SMARTCARDEMULATORCONTRACT_VERSION 0x60000
#endif // defined(WINDOWS_DEVICES_SMARTCARDS_SMARTCARDEMULATORCONTRACT_VERSION)

#if !defined(WINDOWS_DEVICES_SMS_LEGACYSMSAPICONTRACT_VERSION)
#define WINDOWS_DEVICES_SMS_LEGACYSMSAPICONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_DEVICES_SMS_LEGACYSMSAPICONTRACT_VERSION)

#if !defined(WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION)
#define WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION)

#if !defined(WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION)
#define WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION 0x80000
#endif // defined(WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION)

#if !defined(WINDOWS_GAMING_INPUT_GAMINGINPUTPREVIEWCONTRACT_VERSION)
#define WINDOWS_GAMING_INPUT_GAMINGINPUTPREVIEWCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_GAMING_INPUT_GAMINGINPUTPREVIEWCONTRACT_VERSION)

#if !defined(WINDOWS_GLOBALIZATION_GLOBALIZATIONJAPANESEPHONETICANALYZERCONTRACT_VERSION)
#define WINDOWS_GLOBALIZATION_GLOBALIZATIONJAPANESEPHONETICANALYZERCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_GLOBALIZATION_GLOBALIZATIONJAPANESEPHONETICANALYZERCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_APPBROADCASTCONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_APPBROADCASTCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_MEDIA_CAPTURE_APPBROADCASTCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_APPCAPTURECONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_APPCAPTURECONTRACT_VERSION 0x40000
#endif // defined(WINDOWS_MEDIA_CAPTURE_APPCAPTURECONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_APPCAPTUREMETADATACONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_APPCAPTUREMETADATACONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_CAPTURE_APPCAPTUREMETADATACONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_CAMERACAPTUREUICONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_CAMERACAPTUREUICONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_CAPTURE_CAMERACAPTUREUICONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_CAPTURE_GAMEBARCONTRACT_VERSION)
#define WINDOWS_MEDIA_CAPTURE_GAMEBARCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_CAPTURE_GAMEBARCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_DEVICES_CALLCONTROLCONTRACT_VERSION)
#define WINDOWS_MEDIA_DEVICES_CALLCONTROLCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_DEVICES_CALLCONTROLCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_MEDIACONTROLCONTRACT_VERSION)
#define WINDOWS_MEDIA_MEDIACONTROLCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_MEDIACONTROLCONTRACT_VERSION)

#if !defined(WINDOWS_MEDIA_PROTECTION_PROTECTIONRENEWALCONTRACT_VERSION)
#define WINDOWS_MEDIA_PROTECTION_PROTECTIONRENEWALCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_MEDIA_PROTECTION_PROTECTIONRENEWALCONTRACT_VERSION)

#if !defined(WINDOWS_NETWORKING_CONNECTIVITY_WWANCONTRACT_VERSION)
#define WINDOWS_NETWORKING_CONNECTIVITY_WWANCONTRACT_VERSION 0x20000
#endif // defined(WINDOWS_NETWORKING_CONNECTIVITY_WWANCONTRACT_VERSION)

#if !defined(WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION)
#define WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION)

#if !defined(WINDOWS_PHONE_PHONECONTRACT_VERSION)
#define WINDOWS_PHONE_PHONECONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_PHONECONTRACT_VERSION)

#if !defined(WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION)
#define WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION)

#if !defined(WINDOWS_SECURITY_ENTERPRISEDATA_ENTERPRISEDATACONTRACT_VERSION)
#define WINDOWS_SECURITY_ENTERPRISEDATA_ENTERPRISEDATACONTRACT_VERSION 0x50000
#endif // defined(WINDOWS_SECURITY_ENTERPRISEDATA_ENTERPRISEDATACONTRACT_VERSION)

#if !defined(WINDOWS_STORAGE_PROVIDER_CLOUDFILESCONTRACT_VERSION)
#define WINDOWS_STORAGE_PROVIDER_CLOUDFILESCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_STORAGE_PROVIDER_CLOUDFILESCONTRACT_VERSION)

#if !defined(WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION)
#define WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION 0x60000
#endif // defined(WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION)

#if !defined(WINDOWS_UI_CORE_COREWINDOWDIALOGSCONTRACT_VERSION)
#define WINDOWS_UI_CORE_COREWINDOWDIALOGSCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_CORE_COREWINDOWDIALOGSCONTRACT_VERSION)

#if !defined(WINDOWS_UI_VIEWMANAGEMENT_VIEWMANAGEMENTVIEWSCALINGCONTRACT_VERSION)
#define WINDOWS_UI_VIEWMANAGEMENT_VIEWMANAGEMENTVIEWSCALINGCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_VIEWMANAGEMENT_VIEWMANAGEMENTVIEWSCALINGCONTRACT_VERSION)

#if !defined(WINDOWS_UI_WEBUI_CORE_WEBUICOMMANDBARCONTRACT_VERSION)
#define WINDOWS_UI_WEBUI_CORE_WEBUICOMMANDBARCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_WEBUI_CORE_WEBUICOMMANDBARCONTRACT_VERSION)

#endif // defined(SPECIFIC_API_CONTRACT_DEFINITIONS)


// Header files for imported files
#include "inspectable.h"
#include "AsyncInfo.h"
#include "EventToken.h"
#include "windowscontracts.h"
#include "Windows.Foundation.h"
#include "Windows.Storage.h"
#include "Windows.Storage.Streams.h"
#include "Windows.System.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                interface IUserDataAvailabilityStateChangedEventArgs;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs ABI::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                interface IUserDataBufferUnprotectResult;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                interface IUserDataProtectionManager;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager ABI::Windows::Security::DataProtection::IUserDataProtectionManager

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                interface IUserDataProtectionManagerStatics;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics ABI::Windows::Security::DataProtection::IUserDataProtectionManagerStatics

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                interface IUserDataStorageItemProtectionInfo;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                class UserDataBufferUnprotectResult;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b7addeb1-3676-5199-a1fe-bd4f6023119f"))
IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::UserDataBufferUnprotectResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Security::DataProtection::UserDataBufferUnprotectResult*, ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Security.DataProtection.UserDataBufferUnprotectResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::UserDataBufferUnprotectResult*> __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_USE
#define DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("f876652d-ffe1-5c77-a691-2bdb404cfa6f"))
IAsyncOperation<ABI::Windows::Security::DataProtection::UserDataBufferUnprotectResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Security::DataProtection::UserDataBufferUnprotectResult*, ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Security.DataProtection.UserDataBufferUnprotectResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Security::DataProtection::UserDataBufferUnprotectResult*> __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_t;
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult*>
//#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::DataProtection::IUserDataBufferUnprotectResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                class UserDataStorageItemProtectionInfo;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("aa8164da-d880-59f5-8093-664d052d74b5"))
IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo*, ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Security.DataProtection.UserDataStorageItemProtectionInfo>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo*> __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_USE
#define DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("28ff9352-5cb2-5f87-9f08-decacf4f59b3"))
IAsyncOperation<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo*, ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Security.DataProtection.UserDataStorageItemProtectionInfo>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo*> __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_t;
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo*>
//#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                enum UserDataStorageItemProtectionStatus : int;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */


#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("38402d5c-c584-52df-9aea-796867a66835"))
IAsyncOperationCompletedHandler<enum ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> : IAsyncOperationCompletedHandler_impl<enum ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Security.DataProtection.UserDataStorageItemProtectionStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<enum ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_USE */





#ifndef DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_USE
#define DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e5c62dbd-e029-52e1-afd5-73f7a4223de6"))
IAsyncOperation<enum ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> : IAsyncOperation_impl<enum ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Security.DataProtection.UserDataStorageItemProtectionStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<enum ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus> __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_t;
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>
//#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_USE */



namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                class UserDataProtectionManager;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                class UserDataAvailabilityStateChangedEventArgs;
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("82965140-a327-568e-878f-663c2ca7c562"))
ITypedEventHandler<ABI::Windows::Security::DataProtection::UserDataProtectionManager*,ABI::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Security::DataProtection::UserDataProtectionManager*, ABI::Windows::Security::DataProtection::IUserDataProtectionManager*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs*, ABI::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Security.DataProtection.UserDataProtectionManager, Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Security::DataProtection::UserDataProtectionManager*,ABI::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs*> __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Security::DataProtection::IUserDataProtectionManager*,ABI::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Security::DataProtection::IUserDataProtectionManager*,ABI::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            namespace Streams {
                interface IBuffer;
            } /* Streams */
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CStreams_CIBuffer ABI::Windows::Storage::Streams::IBuffer

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("51c3d2fd-b8a1-5620-b746-7ee6d533aca3"))
IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IBuffer*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Storage::Streams::IBuffer*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Storage.Streams.IBuffer>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IBuffer*> __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IBuffer*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IBuffer*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_USE
#define DEF___FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3bee8834-b9a7-5a80-a746-5ef097227878"))
IAsyncOperation<ABI::Windows::Storage::Streams::IBuffer*> : IAsyncOperation_impl<ABI::Windows::Storage::Streams::IBuffer*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Storage.Streams.IBuffer>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Storage::Streams::IBuffer*> __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_t;
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Storage::Streams::IBuffer*>
//#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Storage::Streams::IBuffer*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000



namespace ABI {
    namespace Windows {
        namespace Foundation {
            class Deferral;
        } /* Foundation */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IDeferral;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIDeferral ABI::Windows::Foundation::IDeferral

#endif // ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CStorage_CIStorageItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CIStorageItem_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            interface IStorageItem;
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CIStorageItem ABI::Windows::Storage::IStorageItem

#endif // ____x_ABI_CWindows_CStorage_CIStorageItem_FWD_DEFINED__








namespace ABI {
    namespace Windows {
        namespace System {
            class User;
        } /* System */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            interface IUser;
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CIUser ABI::Windows::System::IUser

#endif // ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__




namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                
                typedef enum UserDataAvailability : int UserDataAvailability;
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                
                typedef enum UserDataBufferUnprotectStatus : int UserDataBufferUnprotectStatus;
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                
                typedef enum UserDataStorageItemProtectionStatus : int UserDataStorageItemProtectionStatus;
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */


















/*
 *
 * Struct Windows.Security.DataProtection.UserDataAvailability
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [v1_enum, contract] */
                enum UserDataAvailability : int
                {
                    UserDataAvailability_Always = 0,
                    UserDataAvailability_AfterFirstUnlock = 1,
                    UserDataAvailability_WhileUnlocked = 2,
                };
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Security.DataProtection.UserDataBufferUnprotectStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [v1_enum, contract] */
                enum UserDataBufferUnprotectStatus : int
                {
                    UserDataBufferUnprotectStatus_Succeeded = 0,
                    UserDataBufferUnprotectStatus_Unavailable = 1,
                };
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Security.DataProtection.UserDataStorageItemProtectionStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [v1_enum, contract] */
                enum UserDataStorageItemProtectionStatus : int
                {
                    UserDataStorageItemProtectionStatus_Succeeded = 0,
                    UserDataStorageItemProtectionStatus_NotProtectable = 1,
                    UserDataStorageItemProtectionStatus_DataUnavailable = 2,
                };
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataAvailabilityStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataAvailabilityStateChangedEventArgs[] = L"Windows.Security.DataProtection.IUserDataAvailabilityStateChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [object, uuid("A76582C9-06A2-4273-A803-834C9F87FBEB"), exclusiveto, contract] */
                MIDL_INTERFACE("A76582C9-06A2-4273-A803-834C9F87FBEB")
                IUserDataAvailabilityStateChangedEventArgs : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserDataAvailabilityStateChangedEventArgs=_uuidof(IUserDataAvailabilityStateChangedEventArgs);
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataBufferUnprotectResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataBufferUnprotectResult
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataBufferUnprotectResult[] = L"Windows.Security.DataProtection.IUserDataBufferUnprotectResult";
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [object, uuid("8EFD0E90-FA9A-46A4-A377-01CEBF1E74D8"), exclusiveto, contract] */
                MIDL_INTERFACE("8EFD0E90-FA9A-46A4-A377-01CEBF1E74D8")
                IUserDataBufferUnprotectResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Security::DataProtection::UserDataBufferUnprotectStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UnprotectedBuffer(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Storage::Streams::IBuffer * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserDataBufferUnprotectResult=_uuidof(IUserDataBufferUnprotectResult);
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataProtectionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataProtectionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataProtectionManager[] = L"Windows.Security.DataProtection.IUserDataProtectionManager";
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [object, uuid("1F13237D-B42E-4A88-9480-0F240924C876"), exclusiveto, contract] */
                MIDL_INTERFACE("1F13237D-B42E-4A88-9480-0F240924C876")
                IUserDataProtectionManager : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE ProtectStorageItemAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::IStorageItem * storageItem,
                        /* [in] */ABI::Windows::Security::DataProtection::UserDataAvailability availability,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetStorageItemProtectionInfoAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::IStorageItem * storageItem,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ProtectBufferAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * unprotectedBuffer,
                        /* [in] */ABI::Windows::Security::DataProtection::UserDataAvailability availability,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UnprotectBufferAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * protectedBuffer,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE IsContinuedDataAvailabilityExpected(
                        /* [in] */ABI::Windows::Security::DataProtection::UserDataAvailability availability,
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_DataAvailabilityStateChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_DataAvailabilityStateChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserDataProtectionManager=_uuidof(IUserDataProtectionManager);
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataProtectionManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataProtectionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataProtectionManagerStatics[] = L"Windows.Security.DataProtection.IUserDataProtectionManagerStatics";
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [object, uuid("977780E8-6DCE-4FAE-AF85-782AC2CF4572"), exclusiveto, contract] */
                MIDL_INTERFACE("977780E8-6DCE-4FAE-AF85-782AC2CF4572")
                IUserDataProtectionManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE TryGetDefault(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Security::DataProtection::IUserDataProtectionManager * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryGetForUser(
                        /* [in] */__RPC__in_opt ABI::Windows::System::IUser * user,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Security::DataProtection::IUserDataProtectionManager * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserDataProtectionManagerStatics=_uuidof(IUserDataProtectionManagerStatics);
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataStorageItemProtectionInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataStorageItemProtectionInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataStorageItemProtectionInfo[] = L"Windows.Security.DataProtection.IUserDataStorageItemProtectionInfo";
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace DataProtection {
                /* [object, uuid("5B6680F6-E87F-40A1-B19D-A6187A0C662F"), exclusiveto, contract] */
                MIDL_INTERFACE("5B6680F6-E87F-40A1-B19D-A6187A0C662F")
                IUserDataStorageItemProtectionInfo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Availability(
                        /* [retval, out] */__RPC__out ABI::Windows::Security::DataProtection::UserDataAvailability * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserDataStorageItemProtectionInfo=_uuidof(IUserDataStorageItemProtectionInfo);
                
            } /* DataProtection */
        } /* Security */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataAvailabilityStateChangedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataAvailabilityStateChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataAvailabilityStateChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataAvailabilityStateChangedEventArgs[] = L"Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataBufferUnprotectResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataBufferUnprotectResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataBufferUnprotectResult_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataBufferUnprotectResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataBufferUnprotectResult[] = L"Windows.Security.DataProtection.UserDataBufferUnprotectResult";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataProtectionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Security.DataProtection.IUserDataProtectionManagerStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataProtectionManager ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataProtectionManager_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataProtectionManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataProtectionManager[] = L"Windows.Security.DataProtection.UserDataProtectionManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataStorageItemProtectionInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataStorageItemProtectionInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataStorageItemProtectionInfo_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataStorageItemProtectionInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataStorageItemProtectionInfo[] = L"Windows.Security.DataProtection.UserDataStorageItemProtectionInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs;

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult;

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager;

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics;

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo;

#endif // ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult;

typedef struct __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResultVtbl;

interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfoVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfoVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo;

typedef struct __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfoVtbl;

interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataStorageItemProtectionStatus;
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatusVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus;

typedef struct __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * This, /* [retval][out] */ __RPC__out enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataStorageItemProtectionStatus *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatusVtbl;

interface __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus_INTERFACE_DEFINED__




#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIBuffer __x_ABI_CWindows_CStorage_CStreams_CIBuffer;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIBuffer_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBufferVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBufferVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBufferVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer;

typedef struct __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBufferVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIBuffer **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CStorage_CStreams_CIBuffer * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBufferVtbl;

interface __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBufferVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#ifndef ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIDeferral __x_ABI_CWindows_CFoundation_CIDeferral;

#endif // ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CStorage_CIStorageItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CIStorageItem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CIStorageItem __x_ABI_CWindows_CStorage_CIStorageItem;

#endif // ____x_ABI_CWindows_CStorage_CIStorageItem_FWD_DEFINED__








#ifndef ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CIUser __x_ABI_CWindows_CSystem_CIUser;

#endif // ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__





typedef enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability;


typedef enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataBufferUnprotectStatus __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataBufferUnprotectStatus;


typedef enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataStorageItemProtectionStatus __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataStorageItemProtectionStatus;


















/*
 *
 * Struct Windows.Security.DataProtection.UserDataAvailability
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability
{
    UserDataAvailability_Always = 0,
    UserDataAvailability_AfterFirstUnlock = 1,
    UserDataAvailability_WhileUnlocked = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Security.DataProtection.UserDataBufferUnprotectStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataBufferUnprotectStatus
{
    UserDataBufferUnprotectStatus_Succeeded = 0,
    UserDataBufferUnprotectStatus_Unavailable = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Security.DataProtection.UserDataStorageItemProtectionStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataStorageItemProtectionStatus
{
    UserDataStorageItemProtectionStatus_Succeeded = 0,
    UserDataStorageItemProtectionStatus_NotProtectable = 1,
    UserDataStorageItemProtectionStatus_DataUnavailable = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataAvailabilityStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataAvailabilityStateChangedEventArgs[] = L"Windows.Security.DataProtection.IUserDataAvailabilityStateChangedEventArgs";
/* [object, uuid("A76582C9-06A2-4273-A803-834C9F87FBEB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgsVtbl;

interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_GetDeferral(This,result) \
    ( (This)->lpVtbl->GetDeferral(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataAvailabilityStateChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataBufferUnprotectResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataBufferUnprotectResult
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataBufferUnprotectResult[] = L"Windows.Security.DataProtection.IUserDataBufferUnprotectResult";
/* [object, uuid("8EFD0E90-FA9A-46A4-A377-01CEBF1E74D8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataBufferUnprotectStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UnprotectedBuffer )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResultVtbl;

interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult
{
    CONST_VTBL struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_get_UnprotectedBuffer(This,value) \
    ( (This)->lpVtbl->get_UnprotectedBuffer(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataBufferUnprotectResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataProtectionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataProtectionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataProtectionManager[] = L"Windows.Security.DataProtection.IUserDataProtectionManager";
/* [object, uuid("1F13237D-B42E-4A88-9480-0F240924C876"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ProtectStorageItemAsync )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CIStorageItem * storageItem,
        /* [in] */__x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability availability,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionStatus * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetStorageItemProtectionInfoAsync )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CIStorageItem * storageItem,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataStorageItemProtectionInfo * * result
        );
    HRESULT ( STDMETHODCALLTYPE *ProtectBufferAsync )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * unprotectedBuffer,
        /* [in] */__x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability availability,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * * result
        );
    HRESULT ( STDMETHODCALLTYPE *UnprotectBufferAsync )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * protectedBuffer,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CSecurity__CDataProtection__CUserDataBufferUnprotectResult * * result
        );
    HRESULT ( STDMETHODCALLTYPE *IsContinuedDataAvailabilityExpected )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */__x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability availability,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_DataAvailabilityStateChanged )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CSecurity__CDataProtection__CUserDataProtectionManager_Windows__CSecurity__CDataProtection__CUserDataAvailabilityStateChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_DataAvailabilityStateChanged )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerVtbl;

interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager
{
    CONST_VTBL struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_ProtectStorageItemAsync(This,storageItem,availability,result) \
    ( (This)->lpVtbl->ProtectStorageItemAsync(This,storageItem,availability,result) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_GetStorageItemProtectionInfoAsync(This,storageItem,result) \
    ( (This)->lpVtbl->GetStorageItemProtectionInfoAsync(This,storageItem,result) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_ProtectBufferAsync(This,unprotectedBuffer,availability,result) \
    ( (This)->lpVtbl->ProtectBufferAsync(This,unprotectedBuffer,availability,result) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_UnprotectBufferAsync(This,protectedBuffer,result) \
    ( (This)->lpVtbl->UnprotectBufferAsync(This,protectedBuffer,result) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_IsContinuedDataAvailabilityExpected(This,availability,value) \
    ( (This)->lpVtbl->IsContinuedDataAvailabilityExpected(This,availability,value) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_add_DataAvailabilityStateChanged(This,handler,token) \
    ( (This)->lpVtbl->add_DataAvailabilityStateChanged(This,handler,token) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_remove_DataAvailabilityStateChanged(This,token) \
    ( (This)->lpVtbl->remove_DataAvailabilityStateChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataProtectionManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataProtectionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataProtectionManagerStatics[] = L"Windows.Security.DataProtection.IUserDataProtectionManagerStatics";
/* [object, uuid("977780E8-6DCE-4FAE-AF85-782AC2CF4572"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *TryGetDefault )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryGetForUser )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSystem_CIUser * user,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManager * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStaticsVtbl;

interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_TryGetDefault(This,result) \
    ( (This)->lpVtbl->TryGetDefault(This,result) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_TryGetForUser(This,user,result) \
    ( (This)->lpVtbl->TryGetForUser(This,user,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataProtectionManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Security.DataProtection.IUserDataStorageItemProtectionInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Security.DataProtection.UserDataStorageItemProtectionInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Security_DataProtection_IUserDataStorageItemProtectionInfo[] = L"Windows.Security.DataProtection.IUserDataStorageItemProtectionInfo";
/* [object, uuid("5B6680F6-E87F-40A1-B19D-A6187A0C662F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Availability )(
        __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSecurity_CDataProtection_CUserDataAvailability * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfoVtbl;

interface __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_get_Availability(This,value) \
    ( (This)->lpVtbl->get_Availability(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo;
#endif /* !defined(____x_ABI_CWindows_CSecurity_CDataProtection_CIUserDataStorageItemProtectionInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataAvailabilityStateChangedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataAvailabilityStateChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataAvailabilityStateChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataAvailabilityStateChangedEventArgs[] = L"Windows.Security.DataProtection.UserDataAvailabilityStateChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataBufferUnprotectResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataBufferUnprotectResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataBufferUnprotectResult_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataBufferUnprotectResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataBufferUnprotectResult[] = L"Windows.Security.DataProtection.UserDataBufferUnprotectResult";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataProtectionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Security.DataProtection.IUserDataProtectionManagerStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataProtectionManager ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataProtectionManager_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataProtectionManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataProtectionManager[] = L"Windows.Security.DataProtection.UserDataProtectionManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Security.DataProtection.UserDataStorageItemProtectionInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Security.DataProtection.IUserDataStorageItemProtectionInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Security_DataProtection_UserDataStorageItemProtectionInfo_DEFINED
#define RUNTIMECLASS_Windows_Security_DataProtection_UserDataStorageItemProtectionInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Security_DataProtection_UserDataStorageItemProtectionInfo[] = L"Windows.Security.DataProtection.UserDataStorageItemProtectionInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Esecurity2Edataprotection_p_h__

#endif // __windows2Esecurity2Edataprotection_h__
