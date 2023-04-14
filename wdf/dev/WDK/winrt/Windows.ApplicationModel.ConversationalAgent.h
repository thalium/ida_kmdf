/* Header file automatically generated from windows.applicationmodel.conversationalagent.idl */
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
#ifndef __windows2Eapplicationmodel2Econversationalagent_h__
#define __windows2Eapplicationmodel2Econversationalagent_h__
#ifndef __windows2Eapplicationmodel2Econversationalagent_p_h__
#define __windows2Eapplicationmodel2Econversationalagent_p_h__


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
#include "Windows.Media.Audio.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                interface IConversationalAgentSession;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                interface IConversationalAgentSessionInterruptedEventArgs;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                interface IConversationalAgentSessionStatics;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                interface IConversationalAgentSignal;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                interface IConversationalAgentSignalDetectedEventArgs;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                interface IConversationalAgentSystemStateChangedEventArgs;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                class ConversationalAgentSession;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("077a96a1-7932-5db3-a503-34a30571f3f2"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("51831e09-6f91-59b0-820d-60b97775c575"))
IAsyncOperation<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*> __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                enum ConversationalAgentSessionUpdateResponse : int;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("6f43477a-01c5-59e2-96e2-1d9a00409159"))
IAsyncOperationCompletedHandler<enum ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> : IAsyncOperationCompletedHandler_impl<enum ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionUpdateResponse>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<enum ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_USE */





#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("4b85887b-8070-5ef9-aac8-92515257061e"))
IAsyncOperation<enum ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> : IAsyncOperation_impl<enum ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionUpdateResponse>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<enum ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse> __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_USE */




namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                class ConversationalAgentSessionInterruptedEventArgs;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e1c093f2-c2f4-58c6-9fd1-3beb13b18ec8"))
ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession, Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionInterruptedEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSessionInterruptedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                class ConversationalAgentSignalDetectedEventArgs;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d4b78ffb-98b2-5004-9cb4-24dd755734fb"))
ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession, Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSignalDetectedEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignalDetectedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                class ConversationalAgentSystemStateChangedEventArgs;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ac7da0c7-d0d3-5bac-bbc9-52ad49131f1f"))
ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs*, ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession, Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangedEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession*,ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSystemStateChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#ifndef DEF___FIAsyncOperationCompletedHandler_1_IInspectable_USE
#define DEF___FIAsyncOperationCompletedHandler_1_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3f08262e-a2e1-5134-9297-e9211f481a2d"))
IAsyncOperationCompletedHandler<IInspectable*> : IAsyncOperationCompletedHandler_impl<IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<IInspectable*> __FIAsyncOperationCompletedHandler_1_IInspectable_t;
#define __FIAsyncOperationCompletedHandler_1_IInspectable ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_IInspectable ABI::Windows::Foundation::IAsyncOperationCompletedHandler<IInspectable*>
//#define __FIAsyncOperationCompletedHandler_1_IInspectable_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_IInspectable_USE */





#ifndef DEF___FIAsyncOperation_1_IInspectable_USE
#define DEF___FIAsyncOperation_1_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("abf53c57-ee50-5342-b52a-26e3b8cc024f"))
IAsyncOperation<IInspectable*> : IAsyncOperation_impl<IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<IInspectable*> __FIAsyncOperation_1_IInspectable_t;
#define __FIAsyncOperation_1_IInspectable ABI::Windows::Foundation::__FIAsyncOperation_1_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_IInspectable ABI::Windows::Foundation::IAsyncOperation<IInspectable*>
//#define __FIAsyncOperation_1_IInspectable_t ABI::Windows::Foundation::IAsyncOperation<IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_IInspectable_USE */



namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Audio {
                class AudioDeviceInputNode;
            } /* Audio */
        } /* Media */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Audio {
                interface IAudioDeviceInputNode;
            } /* Audio */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode ABI::Windows::Media::Audio::IAudioDeviceInputNode

#endif // ____x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("19b1586d-db7d-55e8-9729-2256bd9984d4"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Audio::AudioDeviceInputNode*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Audio::AudioDeviceInputNode*, ABI::Windows::Media::Audio::IAudioDeviceInputNode*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Audio.AudioDeviceInputNode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Audio::AudioDeviceInputNode*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Audio::IAudioDeviceInputNode*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Audio::IAudioDeviceInputNode*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d009b9cb-e9c1-5d8d-9575-c33ac26ce44a"))
IAsyncOperation<ABI::Windows::Media::Audio::AudioDeviceInputNode*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Audio::AudioDeviceInputNode*, ABI::Windows::Media::Audio::IAudioDeviceInputNode*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Audio.AudioDeviceInputNode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Audio::AudioDeviceInputNode*> __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_t;
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Audio::IAudioDeviceInputNode*>
//#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Audio::IAudioDeviceInputNode*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#ifndef DEF___FIAsyncOperationCompletedHandler_1_HSTRING_USE
#define DEF___FIAsyncOperationCompletedHandler_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b79a741f-7fb5-50ae-9e99-911201ec3d41"))
IAsyncOperationCompletedHandler<HSTRING> : IAsyncOperationCompletedHandler_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<HSTRING> __FIAsyncOperationCompletedHandler_1_HSTRING_t;
#define __FIAsyncOperationCompletedHandler_1_HSTRING ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_HSTRING_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_HSTRING ABI::Windows::Foundation::IAsyncOperationCompletedHandler<HSTRING>
//#define __FIAsyncOperationCompletedHandler_1_HSTRING_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_HSTRING_USE */




#ifndef DEF___FIAsyncOperation_1_HSTRING_USE
#define DEF___FIAsyncOperation_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3e1fe603-f897-5263-b328-0806426b8a79"))
IAsyncOperation<HSTRING> : IAsyncOperation_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<HSTRING> __FIAsyncOperation_1_HSTRING_t;
#define __FIAsyncOperation_1_HSTRING ABI::Windows::Foundation::__FIAsyncOperation_1_HSTRING_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_HSTRING ABI::Windows::Foundation::IAsyncOperation<HSTRING>
//#define __FIAsyncOperation_1_HSTRING_t ABI::Windows::Foundation::IAsyncOperation<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_HSTRING_USE */




#ifndef DEF___FIAsyncOperationCompletedHandler_1_UINT32_USE
#define DEF___FIAsyncOperationCompletedHandler_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("9343b6e7-e3d2-5e4a-ab2d-2bce4919a6a4"))
IAsyncOperationCompletedHandler<UINT32> : IAsyncOperationCompletedHandler_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<UINT32> __FIAsyncOperationCompletedHandler_1_UINT32_t;
#define __FIAsyncOperationCompletedHandler_1_UINT32 ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_UINT32_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_UINT32 ABI::Windows::Foundation::IAsyncOperationCompletedHandler<UINT32>
//#define __FIAsyncOperationCompletedHandler_1_UINT32_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_UINT32_USE */




#ifndef DEF___FIAsyncOperation_1_UINT32_USE
#define DEF___FIAsyncOperation_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ef60385f-be78-584b-aaef-7829ada2b0de"))
IAsyncOperation<UINT32> : IAsyncOperation_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<UINT32> __FIAsyncOperation_1_UINT32_t;
#define __FIAsyncOperation_1_UINT32 ABI::Windows::Foundation::__FIAsyncOperation_1_UINT32_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_UINT32 ABI::Windows::Foundation::IAsyncOperation<UINT32>
//#define __FIAsyncOperation_1_UINT32_t ABI::Windows::Foundation::IAsyncOperation<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_UINT32_USE */




#ifndef DEF___FIAsyncOperationCompletedHandler_1_boolean_USE
#define DEF___FIAsyncOperationCompletedHandler_1_boolean_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c1d3d1a2-ae17-5a5f-b5a2-bdcc8844889a"))
IAsyncOperationCompletedHandler<bool> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Boolean>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<bool> __FIAsyncOperationCompletedHandler_1_boolean_t;
#define __FIAsyncOperationCompletedHandler_1_boolean ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_boolean_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_boolean ABI::Windows::Foundation::IAsyncOperationCompletedHandler<boolean>
//#define __FIAsyncOperationCompletedHandler_1_boolean_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<boolean>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_boolean_USE */




#ifndef DEF___FIAsyncOperation_1_boolean_USE
#define DEF___FIAsyncOperation_1_boolean_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("cdb5efb3-5788-509d-9be1-71ccb8a3362a"))
IAsyncOperation<bool> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Boolean>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<bool> __FIAsyncOperation_1_boolean_t;
#define __FIAsyncOperation_1_boolean ABI::Windows::Foundation::__FIAsyncOperation_1_boolean_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_boolean ABI::Windows::Foundation::IAsyncOperation<boolean>
//#define __FIAsyncOperation_1_boolean_t ABI::Windows::Foundation::IAsyncOperation<boolean>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_boolean_USE */




#ifndef DEF___FIIterator_1_UINT32_USE
#define DEF___FIIterator_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("f06a2739-9443-5ef0-b284-dc5aff3e7d10"))
IIterator<UINT32> : IIterator_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<UINT32> __FIIterator_1_UINT32_t;
#define __FIIterator_1_UINT32 ABI::Windows::Foundation::Collections::__FIIterator_1_UINT32_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_UINT32 ABI::Windows::Foundation::Collections::IIterator<UINT32>
//#define __FIIterator_1_UINT32_t ABI::Windows::Foundation::Collections::IIterator<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_UINT32_USE */




#ifndef DEF___FIIterable_1_UINT32_USE
#define DEF___FIIterable_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("421d4b91-b13b-5f37-ae54-b5249bd80539"))
IIterable<UINT32> : IIterable_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<UINT32> __FIIterable_1_UINT32_t;
#define __FIIterable_1_UINT32 ABI::Windows::Foundation::Collections::__FIIterable_1_UINT32_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_UINT32 ABI::Windows::Foundation::Collections::IIterable<UINT32>
//#define __FIIterable_1_UINT32_t ABI::Windows::Foundation::Collections::IIterable<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_UINT32_USE */




#ifndef DEF___FIVectorView_1_UINT32_USE
#define DEF___FIVectorView_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e5ce1a07-8d33-5007-ba64-7d2508ccf85c"))
IVectorView<UINT32> : IVectorView_impl<UINT32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<UInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<UINT32> __FIVectorView_1_UINT32_t;
#define __FIVectorView_1_UINT32 ABI::Windows::Foundation::Collections::__FIVectorView_1_UINT32_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_UINT32 ABI::Windows::Foundation::Collections::IVectorView<UINT32>
//#define __FIVectorView_1_UINT32_t ABI::Windows::Foundation::Collections::IVectorView<UINT32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_UINT32_USE */





#ifndef DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_USE
#define DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("55772f29-da64-5c87-871c-074337a84573"))
IAsyncOperationCompletedHandler<__FIVectorView_1_UINT32*> : IAsyncOperationCompletedHandler_impl<__FIVectorView_1_UINT32*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Foundation.Collections.IVectorView`1<UInt32>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<__FIVectorView_1_UINT32*> __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_t;
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<UINT32>*>
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<UINT32>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_USE */





#ifndef DEF___FIAsyncOperation_1___FIVectorView_1_UINT32_USE
#define DEF___FIAsyncOperation_1___FIVectorView_1_UINT32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("52c56f3c-713a-5162-9e62-362ce7ed53be"))
IAsyncOperation<__FIVectorView_1_UINT32*> : IAsyncOperation_impl<__FIVectorView_1_UINT32*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Foundation.Collections.IVectorView`1<UInt32>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<__FIVectorView_1_UINT32*> __FIAsyncOperation_1___FIVectorView_1_UINT32_t;
#define __FIAsyncOperation_1___FIVectorView_1_UINT32 ABI::Windows::Foundation::__FIAsyncOperation_1___FIVectorView_1_UINT32_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1___FIVectorView_1_UINT32 ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<UINT32>*>
//#define __FIAsyncOperation_1___FIVectorView_1_UINT32_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<UINT32>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1___FIVectorView_1_UINT32_USE */





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
            
            typedef struct TimeSpan TimeSpan;
            
        } /* Foundation */
    } /* Windows */} /* ABI */





namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Audio {
                class AudioGraph;
            } /* Audio */
        } /* Media */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CMedia_CAudio_CIAudioGraph_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CAudio_CIAudioGraph_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Audio {
                interface IAudioGraph;
            } /* Audio */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CAudio_CIAudioGraph ABI::Windows::Media::Audio::IAudioGraph

#endif // ____x_ABI_CWindows_CMedia_CAudio_CIAudioGraph_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                
                typedef enum ConversationalAgentSessionUpdateResponse : int ConversationalAgentSessionUpdateResponse;
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                
                typedef enum ConversationalAgentState : int ConversationalAgentState;
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                
                typedef enum ConversationalAgentSystemStateChangeType : int ConversationalAgentSystemStateChangeType;
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */









namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                class ConversationalAgentSignal;
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */












/*
 *
 * Struct Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionUpdateResponse
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [v1_enum, contract] */
                enum ConversationalAgentSessionUpdateResponse : int
                {
                    ConversationalAgentSessionUpdateResponse_Success = 0,
                    ConversationalAgentSessionUpdateResponse_Failed = 1,
                };
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.ApplicationModel.ConversationalAgent.ConversationalAgentState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [v1_enum, contract] */
                enum ConversationalAgentState : int
                {
                    ConversationalAgentState_Inactive = 0,
                    ConversationalAgentState_Detecting = 1,
                    ConversationalAgentState_Listening = 2,
                    ConversationalAgentState_Working = 3,
                    ConversationalAgentState_Speaking = 4,
                    ConversationalAgentState_ListeningAndSpeaking = 5,
                };
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangeType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [v1_enum, contract] */
                enum ConversationalAgentSystemStateChangeType : int
                {
                    ConversationalAgentSystemStateChangeType_UserAuthentication = 0,
                    ConversationalAgentSystemStateChangeType_ScreenAvailability = 1,
                    ConversationalAgentSystemStateChangeType_IndicatorLightAvailability = 2,
                    ConversationalAgentSystemStateChangeType_VoiceActivationAvailability = 3,
                };
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [object, uuid("DAAAE09A-B7BA-57E5-AD13-DF520F9B6FA7"), exclusiveto, contract] */
                MIDL_INTERFACE("DAAAE09A-B7BA-57E5-AD13-DF520F9B6FA7")
                IConversationalAgentSession : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_SessionInterrupted(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_SessionInterrupted(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_SignalDetected(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_SignalDetected(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_SystemStateChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_SystemStateChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AgentState(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Signal(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSignal * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsIndicatorLightAvailable(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsScreenAvailable(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsUserAuthenticated(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVoiceActivationAvailable(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInterruptible(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInterrupted(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestInterruptibleAsync(
                        /* [in] */::boolean interruptible,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestInterruptible(
                        /* [in] */::boolean interruptible,
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestAgentStateChangeAsync(
                        /* [in] */ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState state,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestAgentStateChange(
                        /* [in] */ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentState state,
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestForegroundActivationAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestForegroundActivation(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSessionUpdateResponse * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAudioClientAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_IInspectable * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAudioClient(
                        /* [retval, out] */__RPC__deref_out_opt IInspectable * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateAudioDeviceInputNodeAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Audio::IAudioGraph * graph,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateAudioDeviceInputNode(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Audio::IAudioGraph * graph,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Audio::IAudioDeviceInputNode * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAudioCaptureDeviceIdAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAudioCaptureDeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAudioRenderDeviceIdAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAudioRenderDeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSignalModelIdAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_UINT32 * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSignalModelId(
                        /* [retval, out] */__RPC__out UINT32 * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetSignalModelIdAsync(
                        /* [in] */UINT32 signalModelId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetSignalModelId(
                        /* [in] */UINT32 signalModelId,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSupportedSignalModelIdsAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_UINT32 * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSupportedSignalModelIds(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT32 * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IConversationalAgentSession=_uuidof(IConversationalAgentSession);
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionInterruptedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [object, uuid("9766591F-F63D-5D3E-9BF2-BD0760552686"), exclusiveto, contract] */
                MIDL_INTERFACE("9766591F-F63D-5D3E-9BF2-BD0760552686")
                IConversationalAgentSessionInterruptedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IConversationalAgentSessionInterruptedEventArgs=_uuidof(IConversationalAgentSessionInterruptedEventArgs);
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionStatics[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [object, uuid("A005166E-E954-576E-BE04-11B8ED10F37B"), exclusiveto, contract] */
                MIDL_INTERFACE("A005166E-E954-576E-BE04-11B8ED10F37B")
                IConversationalAgentSessionStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentSessionAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentSessionSync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::ConversationalAgent::IConversationalAgentSession * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IConversationalAgentSessionStatics=_uuidof(IConversationalAgentSessionStatics);
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [object, uuid("20ED25F7-B120-51F2-8603-265D6A47F232"), exclusiveto, contract] */
                MIDL_INTERFACE("20ED25F7-B120-51F2-8603-265D6A47F232")
                IConversationalAgentSignal : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsSignalVerificationRequired(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsSignalVerificationRequired(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SignalId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SignalId(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SignalName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SignalName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SignalContext(
                        /* [retval, out] */__RPC__deref_out_opt IInspectable * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SignalContext(
                        /* [in] */__RPC__in_opt IInspectable * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SignalStart(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SignalStart(
                        /* [in] */ABI::Windows::Foundation::TimeSpan value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SignalEnd(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SignalEnd(
                        /* [in] */ABI::Windows::Foundation::TimeSpan value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IConversationalAgentSignal=_uuidof(IConversationalAgentSignal);
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignalDetectedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [object, uuid("4D57EB8F-F88A-599B-91D3-D604876708BC"), exclusiveto, contract] */
                MIDL_INTERFACE("4D57EB8F-F88A-599B-91D3-D604876708BC")
                IConversationalAgentSignalDetectedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IConversationalAgentSignalDetectedEventArgs=_uuidof(IConversationalAgentSignalDetectedEventArgs);
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSystemStateChangedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace ConversationalAgent {
                /* [object, uuid("1C2C6E3E-2785-59A7-8E71-38ADEEF79928"), exclusiveto, contract] */
                MIDL_INTERFACE("1C2C6E3E-2785-59A7-8E71-38ADEEF79928")
                IConversationalAgentSystemStateChangedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SystemStateChangeType(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::ConversationalAgent::ConversationalAgentSystemStateChangeType * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IConversationalAgentSystemStateChangedEventArgs=_uuidof(IConversationalAgentSystemStateChangedEventArgs);
                
            } /* ConversationalAgent */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSession_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSession[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSessionInterruptedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSessionInterruptedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSessionInterruptedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignal_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignal_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignal[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignalDetectedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignalDetectedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignalDetectedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSystemStateChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSystemStateChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSystemStateChangedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession;

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal;

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse;
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponseVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponseVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * This, /* [retval][out] */ __RPC__out enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponseVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse_INTERFACE_DEFINED__




#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if !defined(____FIAsyncOperationCompletedHandler_1_IInspectable_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_IInspectable_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_IInspectable __FIAsyncOperationCompletedHandler_1_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_IInspectable;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_IInspectable __FIAsyncOperation_1_IInspectable;

typedef struct __FIAsyncOperationCompletedHandler_1_IInspectableVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_IInspectable * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_IInspectable *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_IInspectableVtbl;

interface __FIAsyncOperationCompletedHandler_1_IInspectable
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_IInspectable_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperation_1_IInspectable_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_IInspectable_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_IInspectable __FIAsyncOperation_1_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_IInspectable;

typedef struct __FIAsyncOperation_1_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_IInspectable * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_IInspectable * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_IInspectable *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_IInspectable * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_IInspectable **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_IInspectable * This, /* [retval][out] */ __RPC__out IInspectable * *results);
    END_INTERFACE
} __FIAsyncOperation_1_IInspectableVtbl;

interface __FIAsyncOperation_1_IInspectable
{
    CONST_VTBL struct __FIAsyncOperation_1_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_IInspectable_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_IInspectable_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_IInspectable_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_IInspectable_INTERFACE_DEFINED__


#ifndef ____x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode __x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode;

#endif // ____x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNodeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNodeVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNodeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNodeVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CAudio__CAudioDeviceInputNode **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNodeVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNodeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#if !defined(____FIAsyncOperationCompletedHandler_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_HSTRING __FIAsyncOperationCompletedHandler_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_HSTRING;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_HSTRING __FIAsyncOperation_1_HSTRING;

typedef struct __FIAsyncOperationCompletedHandler_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_HSTRING * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_HSTRING *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_HSTRINGVtbl;

interface __FIAsyncOperationCompletedHandler_1_HSTRING
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_HSTRING_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperation_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_HSTRING __FIAsyncOperation_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_HSTRING;

typedef struct __FIAsyncOperation_1_HSTRINGVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_HSTRING * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_HSTRING *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_HSTRING **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_HSTRING * This, /* [retval][out] */ __RPC__out HSTRING *results);
    END_INTERFACE
} __FIAsyncOperation_1_HSTRINGVtbl;

interface __FIAsyncOperation_1_HSTRING
{
    CONST_VTBL struct __FIAsyncOperation_1_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_HSTRING_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_HSTRING_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_HSTRING_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperationCompletedHandler_1_UINT32_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_UINT32 __FIAsyncOperationCompletedHandler_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_UINT32;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_UINT32 __FIAsyncOperation_1_UINT32;

typedef struct __FIAsyncOperationCompletedHandler_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_UINT32 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_UINT32 * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_UINT32 *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_UINT32Vtbl;

interface __FIAsyncOperationCompletedHandler_1_UINT32
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_UINT32Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_UINT32_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperation_1_UINT32_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_UINT32 __FIAsyncOperation_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_UINT32;

typedef struct __FIAsyncOperation_1_UINT32Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_UINT32 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_UINT32 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_UINT32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_UINT32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_UINT32 * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_UINT32 *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_UINT32 * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_UINT32 **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_UINT32 * This, /* [retval][out] */ __RPC__out unsigned int *results);
    END_INTERFACE
} __FIAsyncOperation_1_UINT32Vtbl;

interface __FIAsyncOperation_1_UINT32
{
    CONST_VTBL struct __FIAsyncOperation_1_UINT32Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_UINT32_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_UINT32_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_UINT32_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperationCompletedHandler_1_boolean_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_boolean_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_boolean __FIAsyncOperationCompletedHandler_1_boolean;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_boolean;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_boolean __FIAsyncOperation_1_boolean;

typedef struct __FIAsyncOperationCompletedHandler_1_booleanVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_boolean * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_boolean * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_boolean * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_boolean * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_boolean *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_booleanVtbl;

interface __FIAsyncOperationCompletedHandler_1_boolean
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_booleanVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_boolean_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_boolean_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_boolean_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_boolean_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_boolean_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperation_1_boolean_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_boolean_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_boolean __FIAsyncOperation_1_boolean;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_boolean;

typedef struct __FIAsyncOperation_1_booleanVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_boolean * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_boolean * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_boolean * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_boolean * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_boolean * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_boolean * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_boolean * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_boolean *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_boolean * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_boolean **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_boolean * This, /* [retval][out] */ __RPC__out boolean *results);
    END_INTERFACE
} __FIAsyncOperation_1_booleanVtbl;

interface __FIAsyncOperation_1_boolean
{
    CONST_VTBL struct __FIAsyncOperation_1_booleanVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_boolean_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_boolean_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_boolean_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_boolean_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_boolean_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_boolean_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_boolean_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_boolean_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_boolean_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_boolean_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_UINT32_INTERFACE_DEFINED__)
#define ____FIIterator_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIIterator_1_UINT32 __FIIterator_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_UINT32;

typedef struct __FIIterator_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_UINT32 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_UINT32 * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_UINT32 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_UINT32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_UINT32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_UINT32 * This, /* [retval][out] */ __RPC__out unsigned int *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_UINT32 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_UINT32 * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_UINT32 * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned int *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_UINT32Vtbl;

interface __FIIterator_1_UINT32
{
    CONST_VTBL struct __FIIterator_1_UINT32Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_UINT32_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_UINT32_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_UINT32_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_UINT32_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_UINT32_INTERFACE_DEFINED__)
#define ____FIIterable_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIIterable_1_UINT32 __FIIterable_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_UINT32;

typedef  struct __FIIterable_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_UINT32 * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_UINT32 * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_UINT32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_UINT32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_UINT32 * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_UINT32 **first);

    END_INTERFACE
} __FIIterable_1_UINT32Vtbl;

interface __FIIterable_1_UINT32
{
    CONST_VTBL struct __FIIterable_1_UINT32Vtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_UINT32_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_UINT32_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_UINT32_INTERFACE_DEFINED__)
#define ____FIVectorView_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_UINT32 __FIVectorView_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_UINT32;

typedef struct __FIVectorView_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_UINT32 * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_UINT32 * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_UINT32 * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_UINT32 * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_UINT32 * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out unsigned int *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_UINT32 * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_UINT32 * This,
            /* [in] */ unsigned int item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_UINT32 * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) unsigned int *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_UINT32Vtbl;

interface __FIVectorView_1_UINT32
{
    CONST_VTBL struct __FIVectorView_1_UINT32Vtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_UINT32_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_UINT32_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_UINT32_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_UINT32_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_UINT32_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1___FIVectorView_1_UINT32 __FIAsyncOperation_1___FIVectorView_1_UINT32;

typedef struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32Vtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1___FIVectorView_1_UINT32 *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32Vtbl;

interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperation_1___FIVectorView_1_UINT32_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1___FIVectorView_1_UINT32_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1___FIVectorView_1_UINT32 __FIAsyncOperation_1___FIVectorView_1_UINT32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1___FIVectorView_1_UINT32;

typedef struct __FIAsyncOperation_1___FIVectorView_1_UINT32Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_UINT32 **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_UINT32 * This, /* [retval][out] */ __RPC__out __FIVectorView_1_UINT32 * *results);
    END_INTERFACE
} __FIAsyncOperation_1___FIVectorView_1_UINT32Vtbl;

interface __FIAsyncOperation_1___FIVectorView_1_UINT32
{
    CONST_VTBL struct __FIAsyncOperation_1___FIVectorView_1_UINT32Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1___FIVectorView_1_UINT32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1___FIVectorView_1_UINT32_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_UINT32_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1___FIVectorView_1_UINT32_INTERFACE_DEFINED__



#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;





#ifndef ____x_ABI_CWindows_CMedia_CAudio_CIAudioGraph_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CAudio_CIAudioGraph_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CAudio_CIAudioGraph __x_ABI_CWindows_CMedia_CAudio_CIAudioGraph;

#endif // ____x_ABI_CWindows_CMedia_CAudio_CIAudioGraph_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse;


typedef enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentState __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentState;


typedef enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSystemStateChangeType __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSystemStateChangeType;




















/*
 *
 * Struct Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionUpdateResponse
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse
{
    ConversationalAgentSessionUpdateResponse_Success = 0,
    ConversationalAgentSessionUpdateResponse_Failed = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.ApplicationModel.ConversationalAgent.ConversationalAgentState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentState
{
    ConversationalAgentState_Inactive = 0,
    ConversationalAgentState_Detecting = 1,
    ConversationalAgentState_Listening = 2,
    ConversationalAgentState_Working = 3,
    ConversationalAgentState_Speaking = 4,
    ConversationalAgentState_ListeningAndSpeaking = 5,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangeType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSystemStateChangeType
{
    ConversationalAgentSystemStateChangeType_UserAuthentication = 0,
    ConversationalAgentSystemStateChangeType_ScreenAvailability = 1,
    ConversationalAgentSystemStateChangeType_IndicatorLightAvailability = 2,
    ConversationalAgentSystemStateChangeType_VoiceActivationAvailability = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSession[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession";
/* [object, uuid("DAAAE09A-B7BA-57E5-AD13-DF520F9B6FA7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_SessionInterrupted )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionInterruptedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_SessionInterrupted )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_SignalDetected )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSignalDetectedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_SignalDetected )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_SystemStateChanged )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSystemStateChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_SystemStateChanged )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AgentState )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Signal )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsIndicatorLightAvailable )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsScreenAvailable )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsUserAuthenticated )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVoiceActivationAvailable )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInterruptible )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInterrupted )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *RequestInterruptibleAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */boolean interruptible,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestInterruptible )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */boolean interruptible,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse * result
        );
    HRESULT ( STDMETHODCALLTYPE *RequestAgentStateChangeAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentState state,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestAgentStateChange )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentState state,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse * result
        );
    HRESULT ( STDMETHODCALLTYPE *RequestForegroundActivationAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSessionUpdateResponse * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestForegroundActivation )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSessionUpdateResponse * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetAudioClientAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_IInspectable * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAudioClient )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt IInspectable * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateAudioDeviceInputNodeAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CAudio_CIAudioGraph * graph,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CAudio__CAudioDeviceInputNode * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CreateAudioDeviceInputNode )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CAudio_CIAudioGraph * graph,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CAudio_CIAudioDeviceInputNode * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetAudioCaptureDeviceIdAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAudioCaptureDeviceId )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetAudioRenderDeviceIdAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAudioRenderDeviceId )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetSignalModelIdAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_UINT32 * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetSignalModelId )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__out UINT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *SetSignalModelIdAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */UINT32 signalModelId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *SetSignalModelId )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [in] */UINT32 signalModelId,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetSupportedSignalModelIdsAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_UINT32 * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetSupportedSignalModelIds )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_UINT32 * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionVtbl;

interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_add_SessionInterrupted(This,handler,token) \
    ( (This)->lpVtbl->add_SessionInterrupted(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_remove_SessionInterrupted(This,token) \
    ( (This)->lpVtbl->remove_SessionInterrupted(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_add_SignalDetected(This,handler,token) \
    ( (This)->lpVtbl->add_SignalDetected(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_remove_SignalDetected(This,token) \
    ( (This)->lpVtbl->remove_SignalDetected(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_add_SystemStateChanged(This,handler,token) \
    ( (This)->lpVtbl->add_SystemStateChanged(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_remove_SystemStateChanged(This,token) \
    ( (This)->lpVtbl->remove_SystemStateChanged(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_AgentState(This,value) \
    ( (This)->lpVtbl->get_AgentState(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_Signal(This,value) \
    ( (This)->lpVtbl->get_Signal(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_IsIndicatorLightAvailable(This,value) \
    ( (This)->lpVtbl->get_IsIndicatorLightAvailable(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_IsScreenAvailable(This,value) \
    ( (This)->lpVtbl->get_IsScreenAvailable(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_IsUserAuthenticated(This,value) \
    ( (This)->lpVtbl->get_IsUserAuthenticated(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_IsVoiceActivationAvailable(This,value) \
    ( (This)->lpVtbl->get_IsVoiceActivationAvailable(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_IsInterruptible(This,value) \
    ( (This)->lpVtbl->get_IsInterruptible(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_get_IsInterrupted(This,value) \
    ( (This)->lpVtbl->get_IsInterrupted(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_RequestInterruptibleAsync(This,interruptible,operation) \
    ( (This)->lpVtbl->RequestInterruptibleAsync(This,interruptible,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_RequestInterruptible(This,interruptible,result) \
    ( (This)->lpVtbl->RequestInterruptible(This,interruptible,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_RequestAgentStateChangeAsync(This,state,operation) \
    ( (This)->lpVtbl->RequestAgentStateChangeAsync(This,state,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_RequestAgentStateChange(This,state,result) \
    ( (This)->lpVtbl->RequestAgentStateChange(This,state,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_RequestForegroundActivationAsync(This,operation) \
    ( (This)->lpVtbl->RequestForegroundActivationAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_RequestForegroundActivation(This,result) \
    ( (This)->lpVtbl->RequestForegroundActivation(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetAudioClientAsync(This,operation) \
    ( (This)->lpVtbl->GetAudioClientAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetAudioClient(This,result) \
    ( (This)->lpVtbl->GetAudioClient(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_CreateAudioDeviceInputNodeAsync(This,graph,operation) \
    ( (This)->lpVtbl->CreateAudioDeviceInputNodeAsync(This,graph,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_CreateAudioDeviceInputNode(This,graph,result) \
    ( (This)->lpVtbl->CreateAudioDeviceInputNode(This,graph,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetAudioCaptureDeviceIdAsync(This,operation) \
    ( (This)->lpVtbl->GetAudioCaptureDeviceIdAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetAudioCaptureDeviceId(This,result) \
    ( (This)->lpVtbl->GetAudioCaptureDeviceId(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetAudioRenderDeviceIdAsync(This,operation) \
    ( (This)->lpVtbl->GetAudioRenderDeviceIdAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetAudioRenderDeviceId(This,result) \
    ( (This)->lpVtbl->GetAudioRenderDeviceId(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetSignalModelIdAsync(This,operation) \
    ( (This)->lpVtbl->GetSignalModelIdAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetSignalModelId(This,result) \
    ( (This)->lpVtbl->GetSignalModelId(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_SetSignalModelIdAsync(This,signalModelId,operation) \
    ( (This)->lpVtbl->SetSignalModelIdAsync(This,signalModelId,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_SetSignalModelId(This,signalModelId,result) \
    ( (This)->lpVtbl->SetSignalModelId(This,signalModelId,result) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetSupportedSignalModelIdsAsync(This,operation) \
    ( (This)->lpVtbl->GetSupportedSignalModelIdsAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_GetSupportedSignalModelIds(This,result) \
    ( (This)->lpVtbl->GetSupportedSignalModelIds(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionInterruptedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs";
/* [object, uuid("9766591F-F63D-5D3E-9BF2-BD0760552686"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionInterruptedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSessionStatics[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics";
/* [object, uuid("A005166E-E954-576E-BE04-11B8ED10F37B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetCurrentSessionAsync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CConversationalAgent__CConversationalAgentSession * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetCurrentSessionSync )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSession * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_GetCurrentSessionAsync(This,operation) \
    ( (This)->lpVtbl->GetCurrentSessionAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_GetCurrentSessionSync(This,result) \
    ( (This)->lpVtbl->GetCurrentSessionSync(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSessionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignal[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal";
/* [object, uuid("20ED25F7-B120-51F2-8603-265D6A47F232"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsSignalVerificationRequired )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsSignalVerificationRequired )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SignalId )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SignalId )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SignalName )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SignalName )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SignalContext )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [retval, out] */__RPC__deref_out_opt IInspectable * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SignalContext )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [in] */__RPC__in_opt IInspectable * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SignalStart )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SignalStart )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SignalEnd )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SignalEnd )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalVtbl;

interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_get_IsSignalVerificationRequired(This,value) \
    ( (This)->lpVtbl->get_IsSignalVerificationRequired(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_put_IsSignalVerificationRequired(This,value) \
    ( (This)->lpVtbl->put_IsSignalVerificationRequired(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_get_SignalId(This,value) \
    ( (This)->lpVtbl->get_SignalId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_put_SignalId(This,value) \
    ( (This)->lpVtbl->put_SignalId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_get_SignalName(This,value) \
    ( (This)->lpVtbl->get_SignalName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_put_SignalName(This,value) \
    ( (This)->lpVtbl->put_SignalName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_get_SignalContext(This,value) \
    ( (This)->lpVtbl->get_SignalContext(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_put_SignalContext(This,value) \
    ( (This)->lpVtbl->put_SignalContext(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_get_SignalStart(This,value) \
    ( (This)->lpVtbl->get_SignalStart(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_put_SignalStart(This,value) \
    ( (This)->lpVtbl->put_SignalStart(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_get_SignalEnd(This,value) \
    ( (This)->lpVtbl->get_SignalEnd(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_put_SignalEnd(This,value) \
    ( (This)->lpVtbl->put_SignalEnd(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignal_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSignalDetectedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs";
/* [object, uuid("4D57EB8F-F88A-599B-91D3-D604876708BC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSignalDetectedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_ConversationalAgent_IConversationalAgentSystemStateChangedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs";
/* [object, uuid("1C2C6E3E-2785-59A7-8E71-38ADEEF79928"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SystemStateChangeType )(
        __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CConversationalAgentSystemStateChangeType * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_get_SystemStateChangeType(This,value) \
    ( (This)->lpVtbl->get_SystemStateChangeType(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CConversationalAgent_CIConversationalAgentSystemStateChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSession_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSession[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSessionInterruptedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSessionInterruptedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSessionInterruptedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSessionInterruptedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSessionInterruptedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignal ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignal_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignal_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignal[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignal";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSignalDetectedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignalDetectedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignalDetectedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSignalDetectedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSignalDetectedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.ConversationalAgent.IConversationalAgentSystemStateChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSystemStateChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSystemStateChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_ConversationalAgent_ConversationalAgentSystemStateChangedEventArgs[] = L"Windows.ApplicationModel.ConversationalAgent.ConversationalAgentSystemStateChangedEventArgs";
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
#endif // __windows2Eapplicationmodel2Econversationalagent_p_h__

#endif // __windows2Eapplicationmodel2Econversationalagent_h__
