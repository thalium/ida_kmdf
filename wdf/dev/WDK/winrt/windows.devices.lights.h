/* Header file automatically generated from windows.devices.lights.idl */
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
#ifndef __windows2Edevices2Elights_h__
#define __windows2Edevices2Elights_h__
#ifndef __windows2Edevices2Elights_p_h__
#define __windows2Edevices2Elights_p_h__


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
#include "Windows.Foundation.Numerics.h"
#include "Windows.Storage.Streams.h"
#include "Windows.System.h"
#include "Windows.UI.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CLights_CILamp_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILamp_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                interface ILamp;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CILamp ABI::Windows::Devices::Lights::ILamp

#endif // ____x_ABI_CWindows_CDevices_CLights_CILamp_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                interface ILampArray;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CILampArray ABI::Windows::Devices::Lights::ILampArray

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                interface ILampArrayStatics;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics ABI::Windows::Devices::Lights::ILampArrayStatics

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                interface ILampAvailabilityChangedEventArgs;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs ABI::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                interface ILampInfo;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CILampInfo ABI::Windows::Devices::Lights::ILampInfo

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                interface ILampStatics;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CILampStatics ABI::Windows::Devices::Lights::ILampStatics

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                class Lamp;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("191a8c6e-60dd-5a21-a53c-bf3f940a1dde"))
IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::Lamp*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Lamp*, ABI::Windows::Devices::Lights::ILamp*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Devices.Lights.Lamp>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::Lamp*> __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::ILamp*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::ILamp*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_USE
#define DEF___FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("52a69dfd-f0d6-5931-b8e1-f38066d71bf2"))
IAsyncOperation<ABI::Windows::Devices::Lights::Lamp*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Lamp*, ABI::Windows::Devices::Lights::ILamp*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Devices.Lights.Lamp>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Devices::Lights::Lamp*> __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_t;
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Lights::ILamp*>
//#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Lights::ILamp*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                class LampArray;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("eba415db-42af-54b8-a2f3-5b34494c8972"))
IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::LampArray*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::LampArray*, ABI::Windows::Devices::Lights::ILampArray*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Devices.Lights.LampArray>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::LampArray*> __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::ILampArray*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Lights::ILampArray*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_USE
#define DEF___FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3e9a9900-6eb1-5db1-b778-9a64a16542f8"))
IAsyncOperation<ABI::Windows::Devices::Lights::LampArray*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::LampArray*, ABI::Windows::Devices::Lights::ILampArray*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Devices.Lights.LampArray>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Devices::Lights::LampArray*> __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_t;
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Lights::ILampArray*>
//#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Lights::ILampArray*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                class LampAvailabilityChangedEventArgs;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("556a02d9-7685-576f-89ca-b62dc481d29d"))
ITypedEventHandler<ABI::Windows::Devices::Lights::Lamp*,ABI::Windows::Devices::Lights::LampAvailabilityChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Lamp*, ABI::Windows::Devices::Lights::ILamp*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::LampAvailabilityChangedEventArgs*, ABI::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Lights.Lamp, Windows.Devices.Lights.LampAvailabilityChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Lights::Lamp*,ABI::Windows::Devices::Lights::LampAvailabilityChangedEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Lights::ILamp*,ABI::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Lights::ILamp*,ABI::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

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
        namespace UI {
            struct Color;
            
        } /* UI */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CUI__CColor_USE
#define DEF___FIReference_1_Windows__CUI__CColor_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ab8e5d11-b0c1-5a21-95ae-f16bf3a37624"))
IReference<struct ABI::Windows::UI::Color> : IReference_impl<struct ABI::Windows::UI::Color> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.UI.Color>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::UI::Color> __FIReference_1_Windows__CUI__CColor_t;
#define __FIReference_1_Windows__CUI__CColor ABI::Windows::Foundation::__FIReference_1_Windows__CUI__CColor_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CUI__CColor ABI::Windows::Foundation::IReference<ABI::Windows::UI::Color>
//#define __FIReference_1_Windows__CUI__CColor_t ABI::Windows::Foundation::IReference<ABI::Windows::UI::Color>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CUI__CColor_USE */





#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IAsyncAction;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIAsyncAction ABI::Windows::Foundation::IAsyncAction

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IClosable;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIClosable ABI::Windows::Foundation::IClosable

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__




namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Numerics {
                
                typedef struct Vector3 Vector3;
                
            } /* Numerics */
        } /* Foundation */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct TimeSpan TimeSpan;
            
        } /* Foundation */
    } /* Windows */} /* ABI */








namespace ABI {
    namespace Windows {
        namespace System {
            
            typedef enum VirtualKey : int VirtualKey;
            
        } /* System */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            
            typedef struct Color Color;
            
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                
                typedef enum LampArrayKind : int LampArrayKind;
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                
                typedef enum LampPurposes : unsigned int LampPurposes;
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */










namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                class LampInfo;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */










/*
 *
 * Struct Windows.Devices.Lights.LampArrayKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [v1_enum, contract] */
                enum LampArrayKind : int
                {
                    LampArrayKind_Undefined = 0,
                    LampArrayKind_Keyboard = 1,
                    LampArrayKind_Mouse = 2,
                    LampArrayKind_GameController = 3,
                    LampArrayKind_Peripheral = 4,
                    LampArrayKind_Scene = 5,
                    LampArrayKind_Notification = 6,
                    LampArrayKind_Chassis = 7,
                    LampArrayKind_Wearable = 8,
                    LampArrayKind_Furniture = 9,
                    LampArrayKind_Art = 10,
                };
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.Devices.Lights.LampPurposes
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [v1_enum, flags, contract] */
                enum LampPurposes : unsigned int
                {
                    LampPurposes_Undefined = 0,
                    LampPurposes_Control = 0x1,
                    LampPurposes_Accent = 0x2,
                    LampPurposes_Branding = 0x4,
                    LampPurposes_Status = 0x8,
                    LampPurposes_Illumination = 0x10,
                    LampPurposes_Presentation = 0x20,
                };
                
                DEFINE_ENUM_FLAG_OPERATORS(LampPurposes)
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILamp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Lamp
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Foundation.IClosable
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILamp_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILamp_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILamp[] = L"Windows.Devices.Lights.ILamp";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [object, uuid("047D5B9A-EA45-4B2B-B1A2-14DFF00BDE7B"), exclusiveto, contract] */
                MIDL_INTERFACE("047D5B9A-EA45-4B2B-B1A2-14DFF00BDE7B")
                ILamp : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsEnabled(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BrightnessLevel(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BrightnessLevel(
                        /* [in] */FLOAT value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsColorSettable(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Color(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Color(
                        /* [in] */ABI::Windows::UI::Color value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_AvailabilityChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_AvailabilityChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILamp=_uuidof(ILamp);
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILamp;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILamp_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Devices.Lights.ILampArray
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampArray
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampArray_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampArray_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampArray[] = L"Windows.Devices.Lights.ILampArray";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [object, uuid("7ACE9787-C8A0-4E95-A1E0-D58676538649"), exclusiveto, contract] */
                MIDL_INTERFACE("7ACE9787-C8A0-4E95-A1E0-D58676538649")
                ILampArray : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HardwareVendorId(
                        /* [retval, out] */__RPC__out UINT16 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HardwareProductId(
                        /* [retval, out] */__RPC__out UINT16 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HardwareVersion(
                        /* [retval, out] */__RPC__out UINT16 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LampArrayKind(
                        /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::LampArrayKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LampCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MinUpdateInterval(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BoundingBox(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsEnabled(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BrightnessLevel(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BrightnessLevel(
                        /* [in] */DOUBLE value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsConnected(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SupportsVirtualKeys(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetLampInfo(
                        /* [in] */INT32 lampIndex,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Lights::ILampInfo * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetIndicesForKey(
                        /* [in] */ABI::Windows::System::VirtualKey key,
                        /* [out] */__RPC__out UINT32 * __resultSize,
                        /* [size_is(, *(__resultSize)), retval, out] */__RPC__deref_out_ecount_full_opt(*(__resultSize)) INT32 * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetIndicesForPurposes(
                        /* [in] */ABI::Windows::Devices::Lights::LampPurposes purposes,
                        /* [out] */__RPC__out UINT32 * __resultSize,
                        /* [size_is(, *(__resultSize)), retval, out] */__RPC__deref_out_ecount_full_opt(*(__resultSize)) INT32 * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetColor(
                        /* [in] */ABI::Windows::UI::Color desiredColor
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetColorForIndex(
                        /* [in] */INT32 lampIndex,
                        /* [in] */ABI::Windows::UI::Color desiredColor
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetSingleColorForIndices(
                        /* [in] */ABI::Windows::UI::Color desiredColor,
                        /* [in] */UINT32 __lampIndexesSize,
                        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetColorsForIndices(
                        /* [in] */UINT32 __desiredColorsSize,
                        /* [size_is(__desiredColorsSize), in] */__RPC__in_ecount_full(__desiredColorsSize) ABI::Windows::UI::Color * desiredColors,
                        /* [in] */UINT32 __lampIndexesSize,
                        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetColorsForKey(
                        /* [in] */ABI::Windows::UI::Color desiredColor,
                        /* [in] */ABI::Windows::System::VirtualKey key
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetColorsForKeys(
                        /* [in] */UINT32 __desiredColorsSize,
                        /* [size_is(__desiredColorsSize), in] */__RPC__in_ecount_full(__desiredColorsSize) ABI::Windows::UI::Color * desiredColors,
                        /* [in] */UINT32 __keysSize,
                        /* [size_is(__keysSize), in] */__RPC__in_ecount_full(__keysSize) ABI::Windows::System::VirtualKey * keys
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetColorsForPurposes(
                        /* [in] */ABI::Windows::UI::Color desiredColor,
                        /* [in] */ABI::Windows::Devices::Lights::LampPurposes purposes
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SendMessageAsync(
                        /* [in] */INT32 messageId,
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IBuffer * message,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMessageAsync(
                        /* [in] */INT32 messageId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILampArray=_uuidof(ILampArray);
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampArray;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampArray_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILampArrayStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampArray
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampArrayStatics[] = L"Windows.Devices.Lights.ILampArrayStatics";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [object, uuid("7BB8C98D-5FC1-452D-BB1F-4AD410D398FF"), exclusiveto, contract] */
                MIDL_INTERFACE("7BB8C98D-5FC1-452D-BB1F-4AD410D398FF")
                ILampArrayStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDeviceSelector(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE FromIdAsync(
                        /* [in] */__RPC__in HSTRING deviceId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILampArrayStatics=_uuidof(ILampArrayStatics);
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampArrayStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILampAvailabilityChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampAvailabilityChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampAvailabilityChangedEventArgs[] = L"Windows.Devices.Lights.ILampAvailabilityChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [object, uuid("4F6E3DED-07A2-499D-9260-67E304532BA4"), exclusiveto, contract] */
                MIDL_INTERFACE("4F6E3DED-07A2-499D-9260-67E304532BA4")
                ILampAvailabilityChangedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsAvailable(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILampAvailabilityChangedEventArgs=_uuidof(ILampAvailabilityChangedEventArgs);
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Devices.Lights.ILampInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampInfo[] = L"Windows.Devices.Lights.ILampInfo";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [object, uuid("30BB521C-0ACF-49DA-8C10-150B9CF62713"), exclusiveto, contract] */
                MIDL_INTERFACE("30BB521C-0ACF-49DA-8C10-150B9CF62713")
                ILampInfo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Index(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Purposes(
                        /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::LampPurposes * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Position(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RedLevelCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_GreenLevelCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BlueLevelCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_GainLevelCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_FixedColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetNearestSupportedColor(
                        /* [in] */ABI::Windows::UI::Color desiredColor,
                        /* [retval, out] */__RPC__out ABI::Windows::UI::Color * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UpdateLatency(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILampInfo=_uuidof(ILampInfo);
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampInfo;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILampStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Lamp
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampStatics[] = L"Windows.Devices.Lights.ILampStatics";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                /* [object, uuid("A822416C-8885-401E-B821-8E8B38A8E8EC"), exclusiveto, contract] */
                MIDL_INTERFACE("A822416C-8885-401E-B821-8E8B38A8E8EC")
                ILampStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDeviceSelector(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE FromIdAsync(
                        /* [in] */__RPC__in HSTRING deviceId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDefaultAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILampStatics=_uuidof(ILampStatics);
                
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Devices.Lights.Lamp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Lights.ILampStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILamp ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Lamp_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Lamp_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Lamp[] = L"Windows.Devices.Lights.Lamp";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Devices.Lights.LampArray
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Lights.ILampArrayStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILampArray ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_LampArray_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_LampArray_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_LampArray[] = L"Windows.Devices.Lights.LampArray";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.LampAvailabilityChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILampAvailabilityChangedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_LampAvailabilityChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_LampAvailabilityChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_LampAvailabilityChangedEventArgs[] = L"Windows.Devices.Lights.LampAvailabilityChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Devices.Lights.LampInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILampInfo ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_LampInfo_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_LampInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_LampInfo[] = L"Windows.Devices.Lights.LampInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CLights_CILamp_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILamp_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILamp __x_ABI_CWindows_CDevices_CLights_CILamp;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILamp_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILampArray __x_ABI_CWindows_CDevices_CLights_CILampArray;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILampInfo __x_ABI_CWindows_CDevices_CLights_CILampInfo;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILampStatics __x_ABI_CWindows_CDevices_CLights_CILampStatics;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CDevices__CLights__CLamp;

typedef struct __FIAsyncOperation_1_Windows__CDevices__CLights__CLampVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLamp **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CLights_CILamp * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CDevices__CLights__CLampVtbl;

interface __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CDevices__CLights__CLampVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CDevices__CLights__CLamp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArrayVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArrayVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArrayVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray;

typedef struct __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArrayVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CLights__CLampArray **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CLights_CILampArray * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArrayVtbl;

interface __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArrayVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILamp * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

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

struct __x_ABI_CWindows_CUI_CColor;

#if !defined(____FIReference_1_Windows__CUI__CColor_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CUI__CColor_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CUI__CColor __FIReference_1_Windows__CUI__CColor;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CUI__CColor;

typedef struct __FIReference_1_Windows__CUI__CColorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CUI__CColor * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CUI__CColor * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CUI__CColor * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CUI__CColor * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CUI__CColor * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CUI__CColor * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CUI__CColor * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CUI_CColor *value);
    END_INTERFACE
} __FIReference_1_Windows__CUI__CColorVtbl;

interface __FIReference_1_Windows__CUI__CColor
{
    CONST_VTBL struct __FIReference_1_Windows__CUI__CColorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CUI__CColor_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CUI__CColor_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CUI__CColor_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CUI__CColor_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CUI__CColor_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CUI__CColor_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CUI__CColor_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CUI__CColor_INTERFACE_DEFINED__



#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIAsyncAction __x_ABI_CWindows_CFoundation_CIAsyncAction;

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__





typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3 __x_ABI_CWindows_CFoundation_CNumerics_CVector3;





typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;









typedef enum __x_ABI_CWindows_CSystem_CVirtualKey __x_ABI_CWindows_CSystem_CVirtualKey;




typedef struct __x_ABI_CWindows_CUI_CColor __x_ABI_CWindows_CUI_CColor;




typedef enum __x_ABI_CWindows_CDevices_CLights_CLampArrayKind __x_ABI_CWindows_CDevices_CLights_CLampArrayKind;


typedef enum __x_ABI_CWindows_CDevices_CLights_CLampPurposes __x_ABI_CWindows_CDevices_CLights_CLampPurposes;



















/*
 *
 * Struct Windows.Devices.Lights.LampArrayKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CLights_CLampArrayKind
{
    LampArrayKind_Undefined = 0,
    LampArrayKind_Keyboard = 1,
    LampArrayKind_Mouse = 2,
    LampArrayKind_GameController = 3,
    LampArrayKind_Peripheral = 4,
    LampArrayKind_Scene = 5,
    LampArrayKind_Notification = 6,
    LampArrayKind_Chassis = 7,
    LampArrayKind_Wearable = 8,
    LampArrayKind_Furniture = 9,
    LampArrayKind_Art = 10,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.Devices.Lights.LampPurposes
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CDevices_CLights_CLampPurposes
{
    LampPurposes_Undefined = 0,
    LampPurposes_Control = 0x1,
    LampPurposes_Accent = 0x2,
    LampPurposes_Branding = 0x4,
    LampPurposes_Status = 0x8,
    LampPurposes_Illumination = 0x10,
    LampPurposes_Presentation = 0x20,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILamp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Lamp
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Foundation.IClosable
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILamp_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILamp_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILamp[] = L"Windows.Devices.Lights.ILamp";
/* [object, uuid("047D5B9A-EA45-4B2B-B1A2-14DFF00BDE7B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CILampVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILamp * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILamp * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILamp * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILamp * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILamp * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILamp * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeviceId )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsEnabled )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsEnabled )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BrightnessLevel )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BrightnessLevel )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsColorSettable )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Color )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Color )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_AvailabilityChanged )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CLights__CLamp_Windows__CDevices__CLights__CLampAvailabilityChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_AvailabilityChanged )(
        __x_ABI_CWindows_CDevices_CLights_CILamp * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CILampVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CILamp
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CILampVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CILamp_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_get_DeviceId(This,value) \
    ( (This)->lpVtbl->get_DeviceId(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_get_IsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsEnabled(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_put_IsEnabled(This,value) \
    ( (This)->lpVtbl->put_IsEnabled(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_get_BrightnessLevel(This,value) \
    ( (This)->lpVtbl->get_BrightnessLevel(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_put_BrightnessLevel(This,value) \
    ( (This)->lpVtbl->put_BrightnessLevel(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_get_IsColorSettable(This,value) \
    ( (This)->lpVtbl->get_IsColorSettable(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_get_Color(This,value) \
    ( (This)->lpVtbl->get_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_put_Color(This,value) \
    ( (This)->lpVtbl->put_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_add_AvailabilityChanged(This,handler,token) \
    ( (This)->lpVtbl->add_AvailabilityChanged(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CLights_CILamp_remove_AvailabilityChanged(This,token) \
    ( (This)->lpVtbl->remove_AvailabilityChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILamp;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILamp_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Devices.Lights.ILampArray
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampArray
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampArray_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampArray_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampArray[] = L"Windows.Devices.Lights.ILampArray";
/* [object, uuid("7ACE9787-C8A0-4E95-A1E0-D58676538649"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CILampArrayVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArray * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArray * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeviceId )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HardwareVendorId )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out UINT16 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HardwareProductId )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out UINT16 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HardwareVersion )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out UINT16 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LampArrayKind )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CLampArrayKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LampCount )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MinUpdateInterval )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BoundingBox )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsEnabled )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsEnabled )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BrightnessLevel )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BrightnessLevel )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */DOUBLE value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsConnected )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SupportsVirtualKeys )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetLampInfo )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */INT32 lampIndex,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CLights_CILampInfo * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetIndicesForKey )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */__x_ABI_CWindows_CSystem_CVirtualKey key,
        /* [out] */__RPC__out UINT32 * __resultSize,
        /* [size_is(, *(__resultSize)), retval, out] */__RPC__deref_out_ecount_full_opt(*(__resultSize)) INT32 * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetIndicesForPurposes )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CLampPurposes purposes,
        /* [out] */__RPC__out UINT32 * __resultSize,
        /* [size_is(, *(__resultSize)), retval, out] */__RPC__deref_out_ecount_full_opt(*(__resultSize)) INT32 * * result
        );
    HRESULT ( STDMETHODCALLTYPE *SetColor )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorForIndex )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */INT32 lampIndex,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor
        );
    HRESULT ( STDMETHODCALLTYPE *SetSingleColorForIndices )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorsForIndices )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */UINT32 __desiredColorsSize,
        /* [size_is(__desiredColorsSize), in] */__RPC__in_ecount_full(__desiredColorsSize) __x_ABI_CWindows_CUI_CColor * desiredColors,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorsForKey )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor,
        /* [in] */__x_ABI_CWindows_CSystem_CVirtualKey key
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorsForKeys )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */UINT32 __desiredColorsSize,
        /* [size_is(__desiredColorsSize), in] */__RPC__in_ecount_full(__desiredColorsSize) __x_ABI_CWindows_CUI_CColor * desiredColors,
        /* [in] */UINT32 __keysSize,
        /* [size_is(__keysSize), in] */__RPC__in_ecount_full(__keysSize) __x_ABI_CWindows_CSystem_CVirtualKey * keys
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorsForPurposes )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CLampPurposes purposes
        );
    HRESULT ( STDMETHODCALLTYPE *SendMessageAsync )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */INT32 messageId,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIBuffer * message,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMessageAsync )(
        __x_ABI_CWindows_CDevices_CLights_CILampArray * This,
        /* [in] */INT32 messageId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIBuffer * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CILampArrayVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CILampArray
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CILampArrayVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CILampArray_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_DeviceId(This,value) \
    ( (This)->lpVtbl->get_DeviceId(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_HardwareVendorId(This,value) \
    ( (This)->lpVtbl->get_HardwareVendorId(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_HardwareProductId(This,value) \
    ( (This)->lpVtbl->get_HardwareProductId(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_HardwareVersion(This,value) \
    ( (This)->lpVtbl->get_HardwareVersion(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_LampArrayKind(This,value) \
    ( (This)->lpVtbl->get_LampArrayKind(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_LampCount(This,value) \
    ( (This)->lpVtbl->get_LampCount(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_MinUpdateInterval(This,value) \
    ( (This)->lpVtbl->get_MinUpdateInterval(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_BoundingBox(This,value) \
    ( (This)->lpVtbl->get_BoundingBox(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_IsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsEnabled(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_put_IsEnabled(This,value) \
    ( (This)->lpVtbl->put_IsEnabled(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_BrightnessLevel(This,value) \
    ( (This)->lpVtbl->get_BrightnessLevel(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_put_BrightnessLevel(This,value) \
    ( (This)->lpVtbl->put_BrightnessLevel(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_IsConnected(This,value) \
    ( (This)->lpVtbl->get_IsConnected(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_get_SupportsVirtualKeys(This,value) \
    ( (This)->lpVtbl->get_SupportsVirtualKeys(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_GetLampInfo(This,lampIndex,result) \
    ( (This)->lpVtbl->GetLampInfo(This,lampIndex,result) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_GetIndicesForKey(This,key,__resultSize,result) \
    ( (This)->lpVtbl->GetIndicesForKey(This,key,__resultSize,result) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_GetIndicesForPurposes(This,purposes,__resultSize,result) \
    ( (This)->lpVtbl->GetIndicesForPurposes(This,purposes,__resultSize,result) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetColor(This,desiredColor) \
    ( (This)->lpVtbl->SetColor(This,desiredColor) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetColorForIndex(This,lampIndex,desiredColor) \
    ( (This)->lpVtbl->SetColorForIndex(This,lampIndex,desiredColor) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetSingleColorForIndices(This,desiredColor,__lampIndexesSize,lampIndexes) \
    ( (This)->lpVtbl->SetSingleColorForIndices(This,desiredColor,__lampIndexesSize,lampIndexes) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetColorsForIndices(This,__desiredColorsSize,desiredColors,__lampIndexesSize,lampIndexes) \
    ( (This)->lpVtbl->SetColorsForIndices(This,__desiredColorsSize,desiredColors,__lampIndexesSize,lampIndexes) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetColorsForKey(This,desiredColor,key) \
    ( (This)->lpVtbl->SetColorsForKey(This,desiredColor,key) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetColorsForKeys(This,__desiredColorsSize,desiredColors,__keysSize,keys) \
    ( (This)->lpVtbl->SetColorsForKeys(This,__desiredColorsSize,desiredColors,__keysSize,keys) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SetColorsForPurposes(This,desiredColor,purposes) \
    ( (This)->lpVtbl->SetColorsForPurposes(This,desiredColor,purposes) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_SendMessageAsync(This,messageId,message,operation) \
    ( (This)->lpVtbl->SendMessageAsync(This,messageId,message,operation) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArray_RequestMessageAsync(This,messageId,operation) \
    ( (This)->lpVtbl->RequestMessageAsync(This,messageId,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampArray;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampArray_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILampArrayStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampArray
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampArrayStatics[] = L"Windows.Devices.Lights.ILampArrayStatics";
/* [object, uuid("7BB8C98D-5FC1-452D-BB1F-4AD410D398FF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CILampArrayStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDeviceSelector )(
        __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    HRESULT ( STDMETHODCALLTYPE *FromIdAsync )(
        __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics * This,
        /* [in] */__RPC__in HSTRING deviceId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLampArray * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CILampArrayStaticsVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CILampArrayStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_GetDeviceSelector(This,result) \
    ( (This)->lpVtbl->GetDeviceSelector(This,result) )

#define __x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_FromIdAsync(This,deviceId,operation) \
    ( (This)->lpVtbl->FromIdAsync(This,deviceId,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampArrayStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampArrayStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILampAvailabilityChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampAvailabilityChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampAvailabilityChangedEventArgs[] = L"Windows.Devices.Lights.ILampAvailabilityChangedEventArgs";
/* [object, uuid("4F6E3DED-07A2-499D-9260-67E304532BA4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsAvailable )(
        __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_get_IsAvailable(This,value) \
    ( (This)->lpVtbl->get_IsAvailable(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampAvailabilityChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Devices.Lights.ILampInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.LampInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampInfo[] = L"Windows.Devices.Lights.ILampInfo";
/* [object, uuid("30BB521C-0ACF-49DA-8C10-150B9CF62713"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CILampInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Index )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Purposes )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CLampPurposes * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Position )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RedLevelCount )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_GreenLevelCount )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BlueLevelCount )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_GainLevelCount )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_FixedColor )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetNearestSupportedColor )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UpdateLatency )(
        __x_ABI_CWindows_CDevices_CLights_CILampInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CILampInfoVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CILampInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CILampInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_Index(This,value) \
    ( (This)->lpVtbl->get_Index(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_Purposes(This,value) \
    ( (This)->lpVtbl->get_Purposes(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_Position(This,value) \
    ( (This)->lpVtbl->get_Position(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_RedLevelCount(This,value) \
    ( (This)->lpVtbl->get_RedLevelCount(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_GreenLevelCount(This,value) \
    ( (This)->lpVtbl->get_GreenLevelCount(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_BlueLevelCount(This,value) \
    ( (This)->lpVtbl->get_BlueLevelCount(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_GainLevelCount(This,value) \
    ( (This)->lpVtbl->get_GainLevelCount(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_FixedColor(This,value) \
    ( (This)->lpVtbl->get_FixedColor(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_GetNearestSupportedColor(This,desiredColor,result) \
    ( (This)->lpVtbl->GetNearestSupportedColor(This,desiredColor,result) )

#define __x_ABI_CWindows_CDevices_CLights_CILampInfo_get_UpdateLatency(This,value) \
    ( (This)->lpVtbl->get_UpdateLatency(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampInfo;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.ILampStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Lamp
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CILampStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CILampStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_ILampStatics[] = L"Windows.Devices.Lights.ILampStatics";
/* [object, uuid("A822416C-8885-401E-B821-8E8B38A8E8EC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CILampStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDeviceSelector )(
        __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    HRESULT ( STDMETHODCALLTYPE *FromIdAsync )(
        __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
        /* [in] */__RPC__in HSTRING deviceId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetDefaultAsync )(
        __x_ABI_CWindows_CDevices_CLights_CILampStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CLights__CLamp * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CILampStaticsVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CILampStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CILampStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_GetDeviceSelector(This,value) \
    ( (This)->lpVtbl->GetDeviceSelector(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_FromIdAsync(This,deviceId,operation) \
    ( (This)->lpVtbl->FromIdAsync(This,deviceId,operation) )

#define __x_ABI_CWindows_CDevices_CLights_CILampStatics_GetDefaultAsync(This,operation) \
    ( (This)->lpVtbl->GetDefaultAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CILampStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CILampStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Devices.Lights.Lamp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Lights.ILampStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILamp ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Lamp_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Lamp_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Lamp[] = L"Windows.Devices.Lights.Lamp";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Devices.Lights.LampArray
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Lights.ILampArrayStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILampArray ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_LampArray_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_LampArray_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_LampArray[] = L"Windows.Devices.Lights.LampArray";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.LampAvailabilityChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILampAvailabilityChangedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_LampAvailabilityChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_LampAvailabilityChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_LampAvailabilityChangedEventArgs[] = L"Windows.Devices.Lights.LampAvailabilityChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Devices.Lights.LampInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.ILampInfo ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_LampInfo_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_LampInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_LampInfo[] = L"Windows.Devices.Lights.LampInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Edevices2Elights_p_h__

#endif // __windows2Edevices2Elights_h__
