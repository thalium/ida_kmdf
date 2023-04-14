/* Header file automatically generated from windows.applicationmodel.calls.idl */
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
#ifndef __windows2Eapplicationmodel2Ecalls_h__
#define __windows2Eapplicationmodel2Ecalls_h__
#ifndef __windows2Eapplicationmodel2Ecalls_p_h__
#define __windows2Eapplicationmodel2Ecalls_p_h__


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
#include "Windows.ApplicationModel.Contacts.h"
#include "Windows.Devices.Enumeration.h"
#include "Windows.System.h"
#include "Windows.UI.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface ICallAnswerEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs ABI::Windows::ApplicationModel::Calls::ICallAnswerEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface ICallRejectEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs ABI::Windows::ApplicationModel::Calls::ICallRejectEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface ICallStateChangeEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs ABI::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface ILockScreenCallEndCallDeferral;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral ABI::Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface ILockScreenCallEndRequestedEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs ABI::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface ILockScreenCallUI;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IMuteChangeEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs ABI::Windows::ApplicationModel::Calls::IMuteChangeEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallBlockingStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics ABI::Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryEntry;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryEntryAddress;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryEntryAddressFactory;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryEntryQueryOptions;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryEntryReader;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryManagerForUser;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryManagerStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryManagerStatics2;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallHistoryStore;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallManagerStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics ABI::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallManagerStatics2;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 ABI::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallStore;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore ABI::Windows::ApplicationModel::Calls::IPhoneCallStore

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallVideoCapabilities;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneCallVideoCapabilitiesManagerStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneDialOptions;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions ABI::Windows::ApplicationModel::Calls::IPhoneDialOptions

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLine;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine ABI::Windows::ApplicationModel::Calls::IPhoneLine

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLine2;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 ABI::Windows::ApplicationModel::Calls::IPhoneLine2

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineCellularDetails;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails ABI::Windows::ApplicationModel::Calls::IPhoneLineCellularDetails

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineConfiguration;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration ABI::Windows::ApplicationModel::Calls::IPhoneLineConfiguration

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics ABI::Windows::ApplicationModel::Calls::IPhoneLineStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineTransportDevice;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice ABI::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineTransportDeviceStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics ABI::Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineWatcher;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneLineWatcherEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IPhoneVoicemail;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail ABI::Windows::ApplicationModel::Calls::IPhoneVoicemail

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipCallCoordinator;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipCallCoordinator2;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator2

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipCallCoordinator3;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator3

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipCallCoordinator4;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator4

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipCallCoordinatorStatics;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipPhoneCall;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipPhoneCall2;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall2

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                interface IVoipPhoneCall3;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall3

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallHistoryEntry;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("c1cf3870-064a-54d5-afab-d1dc4ee26ccb"))
IIterator<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
//#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("a3f93eea-c846-52c7-aa5a-3306707f6369"))
IIterable<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
//#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("452ce6ed-a06d-58fb-be06-cb4330b7f5c7"))
IVectorView<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
//#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3234244b-abee-561d-b247-79b832822055"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("785e7cca-90e2-5d03-8f23-b3358d09c951"))
IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry*> __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallHistoryStore;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("226a138b-79ea-56d3-adc2-a40db8d8c9b0"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStore*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStore*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.Calls.PhoneCallHistoryStore>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStore*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("0d9a97b0-8796-52bf-80da-b1435fe64a26"))
IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStore*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStore*, ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.Calls.PhoneCallHistoryStore>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStore*> __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallStore;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("27b63bb3-d008-58f5-854d-ddae65a020b9"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallStore*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallStore*, ABI::Windows::ApplicationModel::Calls::IPhoneCallStore*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.Calls.PhoneCallStore>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallStore*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallStore*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallStore*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("871cad28-01e8-53b5-a14b-30316df65907"))
IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallStore*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallStore*, ABI::Windows::ApplicationModel::Calls::IPhoneCallStore*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.Calls.PhoneCallStore>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallStore*> __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallStore*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallStore*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallVideoCapabilities;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e50fc826-3ef3-5669-aa14-eb95903793a5"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities*, ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7b4b280a-e312-5f06-b953-7e482b67cfcf"))
IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities*, ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities*> __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneLine;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("92ce5bfd-1417-55ee-b0b6-298ae78cb179"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneLine*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneLine*, ABI::Windows::ApplicationModel::Calls::IPhoneLine*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.Calls.PhoneLine>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::PhoneLine*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLine*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLine*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d8712730-aa68-5614-a408-b2012463120b"))
IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneLine*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneLine*, ABI::Windows::ApplicationModel::Calls::IPhoneLine*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.Calls.PhoneLine>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::Calls::PhoneLine*> __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneLine*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::IPhoneLine*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                enum VoipPhoneCallResourceReservationStatus : int;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7a27b20f-647a-53fc-80f0-a79d083ce531"))
IAsyncOperationCompletedHandler<enum ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> : IAsyncOperationCompletedHandler_impl<enum ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.Calls.VoipPhoneCallResourceReservationStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<enum ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_USE */





#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("8528be80-7ce9-5668-8e48-469ae5ba9ead"))
IAsyncOperation<enum ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> : IAsyncOperation_impl<enum ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.Calls.VoipPhoneCallResourceReservationStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<enum ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_USE */




#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("1ef6a805-fd84-5756-a180-353dd72db275"))
IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry*> : IAsyncOperationCompletedHandler_impl<__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Foundation.Collections.IVectorView`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry*> __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>*>
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#define DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2258b912-eb70-5361-b20a-731e15bb9097"))
IAsyncOperation<__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry*> : IAsyncOperation_impl<__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Foundation.Collections.IVectorView`1<Windows.ApplicationModel.Calls.PhoneCallHistoryEntry>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<__FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry*> __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t;
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::__FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>*>
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class LockScreenCallUI;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */



#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("addada2a-e5a7-5921-b7e0-17323adf7382"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::LockScreenCallUI*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::LockScreenCallUI*, ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.LockScreenCallUI, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::LockScreenCallUI*,IInspectable*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class LockScreenCallEndRequestedEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("92f7c40e-e7b9-5f68-98f0-56fb89015806"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::LockScreenCallUI*,ABI::Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::LockScreenCallUI*, ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs*, ABI::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.LockScreenCallUI, Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::LockScreenCallUI*,ABI::Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI*,ABI::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::ILockScreenCallUI*,ABI::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7c5f5192-9fc0-5543-9bc4-411482e4ea93"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::PhoneLine*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneLine*, ABI::Windows::ApplicationModel::Calls::IPhoneLine*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.PhoneLine, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::PhoneLine*,IInspectable*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLine*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLine*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneLineWatcher;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d55ce56a-23ac-5185-bf76-2808ec83c78b"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcher*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcher*, ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.PhoneLineWatcher, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcher*,IInspectable*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneLineWatcherEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("727cff26-a887-5361-8924-95f7bab4e25d"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcher*,ABI::Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcher*, ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs*, ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.PhoneLineWatcher, Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::PhoneLineWatcher*,ABI::Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher*,ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher*,ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class VoipCallCoordinator;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class MuteChangeEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ecafec77-4bf6-57b7-86c6-e2feca5b5aee"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipCallCoordinator*,ABI::Windows::ApplicationModel::Calls::MuteChangeEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::VoipCallCoordinator*, ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::MuteChangeEventArgs*, ABI::Windows::ApplicationModel::Calls::IMuteChangeEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.VoipCallCoordinator, Windows.ApplicationModel.Calls.MuteChangeEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipCallCoordinator*,ABI::Windows::ApplicationModel::Calls::MuteChangeEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator*,ABI::Windows::ApplicationModel::Calls::IMuteChangeEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator*,ABI::Windows::ApplicationModel::Calls::IMuteChangeEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class VoipPhoneCall;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class CallAnswerEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d47be4da-c00c-5faa-bfa5-1b11e0c3ccc1"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::CallAnswerEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*, ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::CallAnswerEventArgs*, ABI::Windows::ApplicationModel::Calls::ICallAnswerEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.VoipPhoneCall, Windows.ApplicationModel.Calls.CallAnswerEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::CallAnswerEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::ICallAnswerEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::ICallAnswerEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class CallRejectEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d06255ce-0967-5441-8fe6-ed2e7008197e"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::CallRejectEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*, ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::CallRejectEventArgs*, ABI::Windows::ApplicationModel::Calls::ICallRejectEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.VoipPhoneCall, Windows.ApplicationModel.Calls.CallRejectEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::CallRejectEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::ICallRejectEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::ICallRejectEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class CallStateChangeEventArgs;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("1e00c6cc-e14c-51ce-93f3-0a0a9a3f3eec"))
ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::CallStateChangeEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*, ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::Calls::CallStateChangeEventArgs*, ABI::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.Calls.VoipPhoneCall, Windows.ApplicationModel.Calls.CallStateChangeEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::VoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::CallStateChangeEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall*,ABI::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_USE */


#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


#ifndef DEF___FIIterator_1_HSTRING_USE
#define DEF___FIIterator_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8c304ebb-6615-50a4-8829-879ecd443236"))
IIterator<HSTRING> : IIterator_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<HSTRING> __FIIterator_1_HSTRING_t;
#define __FIIterator_1_HSTRING ABI::Windows::Foundation::Collections::__FIIterator_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_HSTRING ABI::Windows::Foundation::Collections::IIterator<HSTRING>
//#define __FIIterator_1_HSTRING_t ABI::Windows::Foundation::Collections::IIterator<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_HSTRING_USE */




#ifndef DEF___FIIterable_1_HSTRING_USE
#define DEF___FIIterable_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e2fcc7c1-3bfc-5a0b-b2b0-72e769d1cb7e"))
IIterable<HSTRING> : IIterable_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<HSTRING> __FIIterable_1_HSTRING_t;
#define __FIIterable_1_HSTRING ABI::Windows::Foundation::Collections::__FIIterable_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_HSTRING ABI::Windows::Foundation::Collections::IIterable<HSTRING>
//#define __FIIterable_1_HSTRING_t ABI::Windows::Foundation::Collections::IIterable<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_HSTRING_USE */




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



namespace ABI {
    namespace Windows {
        namespace Foundation {
            struct TimeSpan;
            
        } /* Foundation */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CFoundation__CTimeSpan_USE
#define DEF___FIReference_1_Windows__CFoundation__CTimeSpan_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("604d0c4c-91de-5c2a-935f-362f13eaf800"))
IReference<struct ABI::Windows::Foundation::TimeSpan> : IReference_impl<struct ABI::Windows::Foundation::TimeSpan> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Foundation.TimeSpan>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::Foundation::TimeSpan> __FIReference_1_Windows__CFoundation__CTimeSpan_t;
#define __FIReference_1_Windows__CFoundation__CTimeSpan ABI::Windows::Foundation::__FIReference_1_Windows__CFoundation__CTimeSpan_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CFoundation__CTimeSpan ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::TimeSpan>
//#define __FIReference_1_Windows__CFoundation__CTimeSpan_t ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::TimeSpan>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CFoundation__CTimeSpan_USE */




#ifndef DEF___FIVectorView_1_HSTRING_USE
#define DEF___FIVectorView_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("2f13c006-a03a-5f69-b090-75a43e33423e"))
IVectorView<HSTRING> : IVectorView_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<HSTRING> __FIVectorView_1_HSTRING_t;
#define __FIVectorView_1_HSTRING ABI::Windows::Foundation::Collections::__FIVectorView_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_HSTRING ABI::Windows::Foundation::Collections::IVectorView<HSTRING>
//#define __FIVectorView_1_HSTRING_t ABI::Windows::Foundation::Collections::IVectorView<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_HSTRING_USE */




#ifndef DEF___FIVector_1_HSTRING_USE
#define DEF___FIVector_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("98b9acc1-4b56-532e-ac73-03d5291cca90"))
IVector<HSTRING> : IVector_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<HSTRING> __FIVector_1_HSTRING_t;
#define __FIVector_1_HSTRING ABI::Windows::Foundation::Collections::__FIVector_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_HSTRING ABI::Windows::Foundation::Collections::IVector<HSTRING>
//#define __FIVector_1_HSTRING_t ABI::Windows::Foundation::Collections::IVector<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_HSTRING_USE */




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





#ifndef DEF___FIEventHandler_1_IInspectable_USE
#define DEF___FIEventHandler_1_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c50898f6-c536-5f47-8583-8b2c2438a13b"))
IEventHandler<IInspectable*> : IEventHandler_impl<IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.EventHandler`1<Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IEventHandler<IInspectable*> __FIEventHandler_1_IInspectable_t;
#define __FIEventHandler_1_IInspectable ABI::Windows::Foundation::__FIEventHandler_1_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIEventHandler_1_IInspectable ABI::Windows::Foundation::IEventHandler<IInspectable*>
//#define __FIEventHandler_1_IInspectable_t ABI::Windows::Foundation::IEventHandler<IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIEventHandler_1_IInspectable_USE */




#ifndef DEF___FIAsyncOperationCompletedHandler_1_GUID_USE
#define DEF___FIAsyncOperationCompletedHandler_1_GUID_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("5233899b-ba7e-504f-bb83-ceebac62decf"))
IAsyncOperationCompletedHandler<GUID> : IAsyncOperationCompletedHandler_impl<GUID> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Guid>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<GUID> __FIAsyncOperationCompletedHandler_1_GUID_t;
#define __FIAsyncOperationCompletedHandler_1_GUID ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_GUID_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_GUID ABI::Windows::Foundation::IAsyncOperationCompletedHandler<GUID>
//#define __FIAsyncOperationCompletedHandler_1_GUID_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<GUID>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_GUID_USE */




#ifndef DEF___FIAsyncOperation_1_GUID_USE
#define DEF___FIAsyncOperation_1_GUID_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("6607bc41-294b-5975-9c3f-4b49836d0916"))
IAsyncOperation<GUID> : IAsyncOperation_impl<GUID> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Guid>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<GUID> __FIAsyncOperation_1_GUID_t;
#define __FIAsyncOperation_1_GUID ABI::Windows::Foundation::__FIAsyncOperation_1_GUID_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_GUID ABI::Windows::Foundation::IAsyncOperation<GUID>
//#define __FIAsyncOperation_1_GUID_t ABI::Windows::Foundation::IAsyncOperation<GUID>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_GUID_USE */





#ifndef DEF___FIKeyValuePair_2_HSTRING_IInspectable_USE
#define DEF___FIKeyValuePair_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("09335560-6c6b-5a26-9348-97b781132b20"))
IKeyValuePair<HSTRING,IInspectable*> : IKeyValuePair_impl<HSTRING,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IKeyValuePair`2<String, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IKeyValuePair<HSTRING,IInspectable*> __FIKeyValuePair_2_HSTRING_IInspectable_t;
#define __FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIKeyValuePair_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>
//#define __FIKeyValuePair_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIKeyValuePair_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#define DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5db5fa32-707c-5849-a06b-91c8eb9d10e8"))
IIterator<__FIKeyValuePair_2_HSTRING_IInspectable*> : IIterator_impl<__FIKeyValuePair_2_HSTRING_IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Object>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__FIKeyValuePair_2_HSTRING_IInspectable*> __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_t;
#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#define DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("fe2f3d47-5d47-5499-8374-430c7cda0204"))
IIterable<__FIKeyValuePair_2_HSTRING_IInspectable*> : IIterable_impl<__FIKeyValuePair_2_HSTRING_IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Object>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__FIKeyValuePair_2_HSTRING_IInspectable*> __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_t;
#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,IInspectable*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_USE */





#ifndef DEF___FIMapView_2_HSTRING_IInspectable_USE
#define DEF___FIMapView_2_HSTRING_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("bb78502a-f79d-54fa-92c9-90c5039fdf7e"))
IMapView<HSTRING,IInspectable*> : IMapView_impl<HSTRING,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMapView`2<String, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMapView<HSTRING,IInspectable*> __FIMapView_2_HSTRING_IInspectable_t;
#define __FIMapView_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::__FIMapView_2_HSTRING_IInspectable_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMapView_2_HSTRING_IInspectable ABI::Windows::Foundation::Collections::IMapView<HSTRING,IInspectable*>
//#define __FIMapView_2_HSTRING_IInspectable_t ABI::Windows::Foundation::Collections::IMapView<HSTRING,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMapView_2_HSTRING_IInspectable_USE */



namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Enumeration {
                enum DeviceAccessStatus : int;
            } /* Enumeration */
        } /* Devices */
    } /* Windows */} /* ABI */


#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ee154d83-805b-53e8-8469-90715036d013"))
IAsyncOperationCompletedHandler<enum ABI::Windows::Devices::Enumeration::DeviceAccessStatus> : IAsyncOperationCompletedHandler_impl<enum ABI::Windows::Devices::Enumeration::DeviceAccessStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Devices.Enumeration.DeviceAccessStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<enum ABI::Windows::Devices::Enumeration::DeviceAccessStatus> __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Enumeration::DeviceAccessStatus>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Enumeration::DeviceAccessStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_USE */





#ifndef DEF___FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_USE
#define DEF___FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c00bc2f2-a7f8-5f3f-80d1-2808ef6bca10"))
IAsyncOperation<enum ABI::Windows::Devices::Enumeration::DeviceAccessStatus> : IAsyncOperation_impl<enum ABI::Windows::Devices::Enumeration::DeviceAccessStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Devices.Enumeration.DeviceAccessStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<enum ABI::Windows::Devices::Enumeration::DeviceAccessStatus> __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_t;
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Enumeration::DeviceAccessStatus>
//#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Enumeration::DeviceAccessStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_USE */





namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Contacts {
                class Contact;
            } /* Contacts */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CApplicationModel_CContacts_CIContact_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CContacts_CIContact_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Contacts {
                interface IContact;
            } /* Contacts */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CContacts_CIContact ABI::Windows::ApplicationModel::Contacts::IContact

#endif // ____x_ABI_CWindows_CApplicationModel_CContacts_CIContact_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Contacts {
                class ContactPhone;
            } /* Contacts */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Contacts {
                interface IContactPhone;
            } /* Contacts */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone ABI::Windows::ApplicationModel::Contacts::IContactPhone

#endif // ____x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Enumeration {
                
                typedef enum DeviceAccessStatus : int DeviceAccessStatus;
                
            } /* Enumeration */
        } /* Devices */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct DateTime DateTime;
            
        } /* Foundation */
    } /* Windows */} /* ABI */

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


namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct TimeSpan TimeSpan;
            
        } /* Foundation */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Foundation {
            class Uri;
        } /* Foundation */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IUriRuntimeClass;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIUriRuntimeClass ABI::Windows::Foundation::IUriRuntimeClass

#endif // ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__




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
        namespace UI {
            
            typedef struct Color Color;
            
        } /* UI */
    } /* Windows */} /* ABI */






namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum CellularDtmfMode : int CellularDtmfMode;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneAudioRoutingEndpoint : int PhoneAudioRoutingEndpoint;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallHistoryEntryMedia : int PhoneCallHistoryEntryMedia;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallHistoryEntryOtherAppReadAccess : int PhoneCallHistoryEntryOtherAppReadAccess;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallHistoryEntryQueryDesiredMedia : unsigned int PhoneCallHistoryEntryQueryDesiredMedia;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallHistoryEntryRawAddressKind : int PhoneCallHistoryEntryRawAddressKind;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallHistorySourceIdKind : int PhoneCallHistorySourceIdKind;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallHistoryStoreAccessType : int PhoneCallHistoryStoreAccessType;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneCallMedia : int PhoneCallMedia;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneLineNetworkOperatorDisplayTextLocation : int PhoneLineNetworkOperatorDisplayTextLocation;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneLineTransport : int PhoneLineTransport;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneLineWatcherStatus : int PhoneLineWatcherStatus;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneNetworkState : int PhoneNetworkState;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneSimState : int PhoneSimState;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum PhoneVoicemailType : int PhoneVoicemailType;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum VoipPhoneCallMedia : unsigned int VoipPhoneCallMedia;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum VoipPhoneCallRejectReason : int VoipPhoneCallRejectReason;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum VoipPhoneCallResourceReservationStatus : int VoipPhoneCallResourceReservationStatus;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                
                typedef enum VoipPhoneCallState : int VoipPhoneCallState;
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */













































namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class LockScreenCallEndCallDeferral;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */







namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallHistoryEntryAddress;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallHistoryEntryQueryOptions;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallHistoryEntryReader;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneCallHistoryManagerForUser;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */







namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneDialOptions;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneLineCellularDetails;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneLineConfiguration;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneLineTransportDevice;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                class PhoneVoicemail;
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */














/*
 *
 * Struct Windows.ApplicationModel.Calls.CellularDtmfMode
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum CellularDtmfMode : int
                {
                    CellularDtmfMode_Continuous = 0,
                    CellularDtmfMode_Burst = 1,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneAudioRoutingEndpoint
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneAudioRoutingEndpoint : int
                {
                    PhoneAudioRoutingEndpoint_Default = 0,
                    PhoneAudioRoutingEndpoint_Bluetooth = 1,
                    PhoneAudioRoutingEndpoint_Speakerphone = 2,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryMedia
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneCallHistoryEntryMedia : int
                {
                    PhoneCallHistoryEntryMedia_Audio = 0,
                    PhoneCallHistoryEntryMedia_Video = 1,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryOtherAppReadAccess
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneCallHistoryEntryOtherAppReadAccess : int
                {
                    PhoneCallHistoryEntryOtherAppReadAccess_Full = 0,
                    PhoneCallHistoryEntryOtherAppReadAccess_SystemOnly = 1,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryDesiredMedia
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, flags, contract] */
                enum PhoneCallHistoryEntryQueryDesiredMedia : unsigned int
                {
                    PhoneCallHistoryEntryQueryDesiredMedia_None = 0,
                    PhoneCallHistoryEntryQueryDesiredMedia_Audio = 0x1,
                    PhoneCallHistoryEntryQueryDesiredMedia_Video = 0x2,
                    PhoneCallHistoryEntryQueryDesiredMedia_All = 0xffffffff,
                };
                
                DEFINE_ENUM_FLAG_OPERATORS(PhoneCallHistoryEntryQueryDesiredMedia)
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryRawAddressKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneCallHistoryEntryRawAddressKind : int
                {
                    PhoneCallHistoryEntryRawAddressKind_PhoneNumber = 0,
                    PhoneCallHistoryEntryRawAddressKind_Custom = 1,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistorySourceIdKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneCallHistorySourceIdKind : int
                {
                    PhoneCallHistorySourceIdKind_CellularPhoneLineId = 0,
                    PhoneCallHistorySourceIdKind_PackageFamilyName = 1,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryStoreAccessType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneCallHistoryStoreAccessType : int
                {
                    PhoneCallHistoryStoreAccessType_AppEntriesReadWrite = 0,
                    PhoneCallHistoryStoreAccessType_AllEntriesLimitedReadWrite = 1,
                    PhoneCallHistoryStoreAccessType_AllEntriesReadWrite = 2,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallMedia
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneCallMedia : int
                {
                    PhoneCallMedia_Audio = 0,
                    PhoneCallMedia_AudioAndVideo = 1,
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x40000
                    
                    PhoneCallMedia_AudioAndRealTimeText = 2,
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x40000
                    
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneLineNetworkOperatorDisplayTextLocation
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneLineNetworkOperatorDisplayTextLocation : int
                {
                    PhoneLineNetworkOperatorDisplayTextLocation_Default = 0,
                    PhoneLineNetworkOperatorDisplayTextLocation_Tile = 1,
                    PhoneLineNetworkOperatorDisplayTextLocation_Dialer = 2,
                    PhoneLineNetworkOperatorDisplayTextLocation_InCallUI = 3,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneLineTransport
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneLineTransport : int
                {
                    PhoneLineTransport_Cellular = 0,
                    PhoneLineTransport_VoipApp = 1,
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
                    
                    PhoneLineTransport_Bluetooth = 2,
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
                    
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneLineWatcherStatus
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneLineWatcherStatus : int
                {
                    PhoneLineWatcherStatus_Created = 0,
                    PhoneLineWatcherStatus_Started = 1,
                    PhoneLineWatcherStatus_EnumerationCompleted = 2,
                    PhoneLineWatcherStatus_Stopped = 3,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneNetworkState
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneNetworkState : int
                {
                    PhoneNetworkState_Unknown = 0,
                    PhoneNetworkState_NoSignal = 1,
                    PhoneNetworkState_Deregistered = 2,
                    PhoneNetworkState_Denied = 3,
                    PhoneNetworkState_Searching = 4,
                    PhoneNetworkState_Home = 5,
                    PhoneNetworkState_RoamingInternational = 6,
                    PhoneNetworkState_RoamingDomestic = 7,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneSimState
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneSimState : int
                {
                    PhoneSimState_Unknown = 0,
                    PhoneSimState_PinNotRequired = 1,
                    PhoneSimState_PinUnlocked = 2,
                    PhoneSimState_PinLocked = 3,
                    PhoneSimState_PukLocked = 4,
                    PhoneSimState_NotInserted = 5,
                    PhoneSimState_Invalid = 6,
                    PhoneSimState_Disabled = 7,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneVoicemailType
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum PhoneVoicemailType : int
                {
                    PhoneVoicemailType_None = 0,
                    PhoneVoicemailType_Traditional = 1,
                    PhoneVoicemailType_Visual = 2,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallMedia
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, flags, contract] */
                enum VoipPhoneCallMedia : unsigned int
                {
                    VoipPhoneCallMedia_None = 0,
                    VoipPhoneCallMedia_Audio = 0x1,
                    VoipPhoneCallMedia_Video = 0x2,
                };
                
                DEFINE_ENUM_FLAG_OPERATORS(VoipPhoneCallMedia)
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallRejectReason
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum VoipPhoneCallRejectReason : int
                {
                    VoipPhoneCallRejectReason_UserIgnored = 0,
                    VoipPhoneCallRejectReason_TimedOut = 1,
                    VoipPhoneCallRejectReason_OtherIncomingCall = 2,
                    VoipPhoneCallRejectReason_EmergencyCallExists = 3,
                    VoipPhoneCallRejectReason_InvalidCallState = 4,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallResourceReservationStatus
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum VoipPhoneCallResourceReservationStatus : int
                {
                    VoipPhoneCallResourceReservationStatus_Success = 0,
                    VoipPhoneCallResourceReservationStatus_ResourcesNotAvailable = 1,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallState
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [v1_enum, contract] */
                enum VoipPhoneCallState : int
                {
                    VoipPhoneCallState_Ended = 0,
                    VoipPhoneCallState_Held = 1,
                    VoipPhoneCallState_Active = 2,
                    VoipPhoneCallState_Incoming = 3,
                    VoipPhoneCallState_Outgoing = 4,
                };
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ICallAnswerEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.CallAnswerEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ICallAnswerEventArgs[] = L"Windows.ApplicationModel.Calls.ICallAnswerEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("FD789617-2DD7-4C8C-B2BD-95D17A5BB733"), exclusiveto, contract] */
                MIDL_INTERFACE("FD789617-2DD7-4C8C-B2BD-95D17A5BB733")
                ICallAnswerEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AcceptedMedia(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ICallAnswerEventArgs=_uuidof(ICallAnswerEventArgs);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ICallRejectEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.CallRejectEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ICallRejectEventArgs[] = L"Windows.ApplicationModel.Calls.ICallRejectEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("DA47FAD7-13D4-4D92-A1C2-B77811EE37EC"), exclusiveto, contract] */
                MIDL_INTERFACE("DA47FAD7-13D4-4D92-A1C2-B77811EE37EC")
                ICallRejectEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RejectReason(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::VoipPhoneCallRejectReason * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ICallRejectEventArgs=_uuidof(ICallRejectEventArgs);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ICallStateChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.CallStateChangeEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ICallStateChangeEventArgs[] = L"Windows.ApplicationModel.Calls.ICallStateChangeEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("EAB2349E-66F5-47F9-9FB5-459C5198C720"), exclusiveto, contract] */
                MIDL_INTERFACE("EAB2349E-66F5-47F9-9FB5-459C5198C720")
                ICallStateChangeEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_State(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::VoipPhoneCallState * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ICallStateChangeEventArgs=_uuidof(ICallStateChangeEventArgs);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ILockScreenCallEndCallDeferral
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.LockScreenCallEndCallDeferral
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ILockScreenCallEndCallDeferral[] = L"Windows.ApplicationModel.Calls.ILockScreenCallEndCallDeferral";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("2DD7ED0D-98ED-4041-9632-50FF812B773F"), exclusiveto, contract] */
                MIDL_INTERFACE("2DD7ED0D-98ED-4041-9632-50FF812B773F")
                ILockScreenCallEndCallDeferral : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Complete(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILockScreenCallEndCallDeferral=_uuidof(ILockScreenCallEndCallDeferral);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ILockScreenCallEndRequestedEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ILockScreenCallEndRequestedEventArgs[] = L"Windows.ApplicationModel.Calls.ILockScreenCallEndRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("8190A363-6F27-46E9-AEB6-C0AE83E47DC7"), exclusiveto, contract] */
                MIDL_INTERFACE("8190A363-6F27-46E9-AEB6-C0AE83E47DC7")
                ILockScreenCallEndRequestedEventArgs : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Deadline(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILockScreenCallEndRequestedEventArgs=_uuidof(ILockScreenCallEndRequestedEventArgs);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ILockScreenCallUI
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.LockScreenCallUI
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ILockScreenCallUI[] = L"Windows.ApplicationModel.Calls.ILockScreenCallUI";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("C596FD8D-73C9-4A14-B021-EC1C50A3B727"), exclusiveto, contract] */
                MIDL_INTERFACE("C596FD8D-73C9-4A14-B021-EC1C50A3B727")
                ILockScreenCallUI : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Dismiss(void) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_EndRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_EndRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Closed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Closed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CallTitle(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_CallTitle(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ILockScreenCallUI=_uuidof(ILockScreenCallUI);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IMuteChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.MuteChangeEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IMuteChangeEventArgs[] = L"Windows.ApplicationModel.Calls.IMuteChangeEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("8585E159-0C41-432C-814D-C5F1FDF530BE"), exclusiveto, contract] */
                MIDL_INTERFACE("8585E159-0C41-432C-814D-C5F1FDF530BE")
                IMuteChangeEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Muted(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMuteChangeEventArgs=_uuidof(IMuteChangeEventArgs);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallBlockingStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallBlocking
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallBlockingStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("19646F84-2B79-26F1-A46F-694BE043F313"), exclusiveto, contract] */
                MIDL_INTERFACE("19646F84-2B79-26F1-A46F-694BE043F313")
                IPhoneCallBlockingStatics : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BlockUnknownNumbers(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BlockUnknownNumbers(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BlockPrivateNumbers(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BlockPrivateNumbers(
                        /* [in] */::boolean value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetCallBlockingListAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * phoneNumberList,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallBlockingStatics=_uuidof(IPhoneCallBlockingStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntry
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntry
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntry";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("FAB0E129-32A4-4B85-83D1-F90D8C23A857"), exclusiveto, contract] */
                MIDL_INTERFACE("FAB0E129-32A4-4B85-83D1-F90D8C23A857")
                IPhoneCallHistoryEntry : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Address(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Address(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Duration(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CTimeSpan * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Duration(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CFoundation__CTimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsCallerIdBlocked(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsCallerIdBlocked(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsEmergency(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsEmergency(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsIncoming(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsIncoming(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsMissed(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsMissed(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRinging(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsRinging(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsSeen(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsSeen(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsSuppressed(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsSuppressed(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVoicemail(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsVoicemail(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Media(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Media(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OtherAppReadAccess(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_OtherAppReadAccess(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RemoteId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RemoteId(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SourceDisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SourceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SourceId(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SourceIdKind(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SourceIdKind(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StartTime(
                        /* [in] */ABI::Windows::Foundation::DateTime value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryEntry=_uuidof(IPhoneCallHistoryEntry);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddress
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddress";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("30F159DA-3955-4042-84E6-66EEBF82E67F"), exclusiveto, contract] */
                MIDL_INTERFACE("30F159DA-3955-4042-84E6-66EEBF82E67F")
                IPhoneCallHistoryEntryAddress : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContactId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ContactId(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DisplayName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawAddress(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RawAddress(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawAddressKind(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RawAddressKind(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryEntryAddress=_uuidof(IPhoneCallHistoryEntryAddress);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddressFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddressFactory[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddressFactory";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("FB0FADBA-C7F0-4BB6-9F6B-BA5D73209ACA"), exclusiveto, contract] */
                MIDL_INTERFACE("FB0FADBA-C7F0-4BB6-9F6B-BA5D73209ACA")
                IPhoneCallHistoryEntryAddressFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [in] */__RPC__in HSTRING rawAddress,
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind rawAddressKind,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryEntryAddressFactory=_uuidof(IPhoneCallHistoryEntryAddressFactory);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryQueryOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryOptions
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryQueryOptions[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryQueryOptions";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("9C5FE15C-8BED-40CA-B06E-C4CA8EAE5C87"), exclusiveto, contract] */
                MIDL_INTERFACE("9C5FE15C-8BED-40CA-B06E-C4CA8EAE5C87")
                IPhoneCallHistoryEntryQueryOptions : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DesiredMedia(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DesiredMedia(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SourceIds(
                        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_HSTRING * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryEntryQueryOptions=_uuidof(IPhoneCallHistoryEntryQueryOptions);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryReader
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryReader
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryReader[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryReader";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("61ECE4BE-8D86-479F-8404-A9846920FEE6"), exclusiveto, contract] */
                MIDL_INTERFACE("61ECE4BE-8D86-479F-8404-A9846920FEE6")
                IPhoneCallHistoryEntryReader : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE ReadBatchAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryEntryReader=_uuidof(IPhoneCallHistoryEntryReader);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerForUser
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryManagerForUser
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerForUser[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerForUser";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("D925C523-F55F-4353-9DB4-0205A5265A55"), exclusiveto, contract] */
                MIDL_INTERFACE("D925C523-F55F-4353-9DB4-0205A5265A55")
                IPhoneCallHistoryManagerForUser : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE RequestStoreAsync(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType accessType,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_User(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::System::IUser * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryManagerForUser=_uuidof(IPhoneCallHistoryManagerForUser);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("F5A6DA39-B31F-4F45-AC8E-1B08893C1B50"), exclusiveto, contract] */
                MIDL_INTERFACE("F5A6DA39-B31F-4F45-AC8E-1B08893C1B50")
                IPhoneCallHistoryManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE RequestStoreAsync(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType accessType,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryManagerStatics=_uuidof(IPhoneCallHistoryManagerStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerStatics2[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("EFD474F0-A2DB-4188-9E92-BC3CFA6813CF"), exclusiveto, contract] */
                MIDL_INTERFACE("EFD474F0-A2DB-4188-9E92-BC3CFA6813CF")
                IPhoneCallHistoryManagerStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetForUser(
                        /* [in] */__RPC__in_opt ABI::Windows::System::IUser * user,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryManagerStatics2=_uuidof(IPhoneCallHistoryManagerStatics2);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryStore
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryStore
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryStore";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("2F907DB8-B40E-422B-8545-CB1910A61C52"), exclusiveto, contract] */
                MIDL_INTERFACE("2F907DB8-B40E-422B-8545-CB1910A61C52")
                IPhoneCallHistoryStore : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetEntryAsync(
                        /* [in] */__RPC__in HSTRING callHistoryEntryId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE GetEntryReader(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE GetEntryReaderWithOptions(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions * queryOptions,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SaveEntryAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry * callHistoryEntry,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DeleteEntryAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry * callHistoryEntry,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DeleteEntriesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * callHistoryEntries,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE MarkEntryAsSeenAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry * callHistoryEntry,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE MarkEntriesAsSeenAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * callHistoryEntries,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetUnseenCountAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_UINT32 * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE MarkAllAsSeenAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSourcesUnseenCountAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * sourceIds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_UINT32 * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE MarkSourcesAsSeenAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * sourceIds,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallHistoryStore=_uuidof(IPhoneCallHistoryStore);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallManagerStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallManager
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallManagerStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("60EDAC78-78A6-4872-A3EF-98325EC8B843"), exclusiveto, contract] */
                MIDL_INTERFACE("60EDAC78-78A6-4872-A3EF-98325EC8B843")
                IPhoneCallManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE ShowPhoneCallUI(
                        /* [in] */__RPC__in HSTRING phoneNumber,
                        /* [in] */__RPC__in HSTRING displayName
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallManagerStatics=_uuidof(IPhoneCallManagerStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallManagerStatics2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallManager
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2[] = L"Windows.ApplicationModel.Calls.IPhoneCallManagerStatics2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("C7E3C8BC-2370-431C-98FD-43BE5F03086D"), exclusiveto, contract] */
                MIDL_INTERFACE("C7E3C8BC-2370-431C-98FD-43BE5F03086D")
                IPhoneCallManagerStatics2 : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_CallStateChanged(
                        /* [in] */__RPC__in_opt __FIEventHandler_1_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_CallStateChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsCallActive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsCallIncoming(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ShowPhoneCallSettingsUI(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestStoreAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallManagerStatics2=_uuidof(IPhoneCallManagerStatics2);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallStore
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallStore
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallStore[] = L"Windows.ApplicationModel.Calls.IPhoneCallStore";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("5F610748-18A6-4173-86D1-28BE9DC62DBA"), exclusiveto, contract] */
                MIDL_INTERFACE("5F610748-18A6-4173-86D1-28BE9DC62DBA")
                IPhoneCallStore : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE IsEmergencyPhoneNumberAsync(
                        /* [in] */__RPC__in HSTRING number,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDefaultLineAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_GUID * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestLineWatcher(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneLineWatcher * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallStore=_uuidof(IPhoneCallStore);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilities
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallVideoCapabilities[] = L"Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilities";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("02382786-B16A-4FDB-BE3B-C4240E13AD0D"), exclusiveto, contract] */
                MIDL_INTERFACE("02382786-B16A-4FDB-BE3B-C4240E13AD0D")
                IPhoneCallVideoCapabilities : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVideoCallingCapable(
                        /* [retval, out] */__RPC__out ::boolean * pValue
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallVideoCapabilities=_uuidof(IPhoneCallVideoCapabilities);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilitiesManagerStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallVideoCapabilitiesManager
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallVideoCapabilitiesManagerStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilitiesManagerStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("F3C64B56-F00B-4A1C-A0C6-EE1910749CE7"), exclusiveto, contract] */
                MIDL_INTERFACE("F3C64B56-F00B-4A1C-A0C6-EE1910749CE7")
                IPhoneCallVideoCapabilitiesManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetCapabilitiesAsync(
                        /* [in] */__RPC__in HSTRING phoneNumber,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneCallVideoCapabilitiesManagerStatics=_uuidof(IPhoneCallVideoCapabilitiesManagerStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneDialOptions
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneDialOptions
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneDialOptions[] = L"Windows.ApplicationModel.Calls.IPhoneDialOptions";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("B639C4B8-F06F-36CB-A863-823742B5F2D4"), exclusiveto, contract] */
                MIDL_INTERFACE("B639C4B8-F06F-36CB-A863-823742B5F2D4")
                IPhoneDialOptions : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Number(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Number(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DisplayName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Contact(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Contacts::IContact * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Contact(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Contacts::IContact * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContactPhone(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Contacts::IContactPhone * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ContactPhone(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Contacts::IContactPhone * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Media(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneCallMedia * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Media(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneCallMedia value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AudioEndpoint(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AudioEndpoint(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneDialOptions=_uuidof(IPhoneDialOptions);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLine
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLine
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLine[] = L"Windows.ApplicationModel.Calls.IPhoneLine";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("27C66F30-6A69-34CA-A2BA-65302530C311"), exclusiveto, contract] */
                MIDL_INTERFACE("27C66F30-6A69-34CA-A2BA-65302530C311")
                IPhoneLine : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LineChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LineChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                        /* [retval, out] */__RPC__out GUID * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayColor(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NetworkState(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneNetworkState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Voicemail(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneVoicemail * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NetworkName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CellularDetails(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneLineCellularDetails * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Transport(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneLineTransport * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanDial(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SupportsTile(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_VideoCallingCapabilities(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LineConfiguration(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneLineConfiguration * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE IsImmediateDialNumberAsync(
                        /* [in] */__RPC__in HSTRING number,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Dial(
                        /* [in] */__RPC__in HSTRING number,
                        /* [in] */__RPC__in HSTRING displayName
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DialWithOptions(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Calls::IPhoneDialOptions * options
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLine=_uuidof(IPhoneLine);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLine2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLine
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLine2[] = L"Windows.ApplicationModel.Calls.IPhoneLine2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("0167F56A-5344-5D64-8AF3-A31A950E916A"), exclusiveto, contract] */
                MIDL_INTERFACE("0167F56A-5344-5D64-8AF3-A31A950E916A")
                IPhoneLine2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE EnableTextReply(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TransportDeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLine2=_uuidof(IPhoneLine2);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineCellularDetails
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineCellularDetails
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails[] = L"Windows.ApplicationModel.Calls.IPhoneLineCellularDetails";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("192601D5-147C-4769-B673-98A5EC8426CB"), exclusiveto, contract] */
                MIDL_INTERFACE("192601D5-147C-4769-B673-98A5EC8426CB")
                IPhoneLineCellularDetails : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SimState(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneSimState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SimSlotIndex(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsModemOn(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RegistrationRejectCode(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetNetworkOperatorDisplayText(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneLineNetworkOperatorDisplayTextLocation location,
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineCellularDetails=_uuidof(IPhoneLineCellularDetails);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineConfiguration
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineConfiguration
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineConfiguration[] = L"Windows.ApplicationModel.Calls.IPhoneLineConfiguration";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("FE265862-F64F-4312-B2A8-4E257721AA95"), exclusiveto, contract] */
                MIDL_INTERFACE("FE265862-F64F-4312-B2A8-4E257721AA95")
                IPhoneLineConfiguration : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVideoCallingEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedProperties(
                        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineConfiguration=_uuidof(IPhoneLineConfiguration);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLine
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineStatics[] = L"Windows.ApplicationModel.Calls.IPhoneLineStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("F38B5F23-CEB0-404F-BCF2-BA9F697D8ADF"), exclusiveto, contract] */
                MIDL_INTERFACE("F38B5F23-CEB0-404F-BCF2-BA9F697D8ADF")
                IPhoneLineStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE FromIdAsync(
                        /* [in] */GUID lineId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineStatics=_uuidof(IPhoneLineStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineTransportDevice
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineTransportDevice
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice[] = L"Windows.ApplicationModel.Calls.IPhoneLineTransportDevice";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("EFA8F889-CFFA-59F4-97E4-74705B7DC490"), exclusiveto, contract] */
                MIDL_INTERFACE("EFA8F889-CFFA-59F4-97E4-74705B7DC490")
                IPhoneLineTransportDevice : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Transport(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneLineTransport * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestAccessAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RegisterApp(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RegisterAppForUser(
                        /* [in] */__RPC__in_opt ABI::Windows::System::IUser * user
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UnregisterApp(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UnregisterAppForUser(
                        /* [in] */__RPC__in_opt ABI::Windows::System::IUser * user
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE IsRegistered(
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Connect(
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ConnectAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineTransportDevice=_uuidof(IPhoneLineTransportDevice);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineTransportDeviceStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineTransportDevice
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineTransportDeviceStatics[] = L"Windows.ApplicationModel.Calls.IPhoneLineTransportDeviceStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("0F3121AC-D609-51A1-96F3-FB00D1819252"), exclusiveto, contract] */
                MIDL_INTERFACE("0F3121AC-D609-51A1-96F3-FB00D1819252")
                IPhoneLineTransportDeviceStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE FromId(
                        /* [in] */__RPC__in HSTRING id,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE GetDeviceSelector(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE GetDeviceSelectorForPhoneLineTransport(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::PhoneLineTransport transport,
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineTransportDeviceStatics=_uuidof(IPhoneLineTransportDeviceStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineWatcher
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineWatcher
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineWatcher[] = L"Windows.ApplicationModel.Calls.IPhoneLineWatcher";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("8A45CD0A-6323-44E0-A6F6-9F21F64DC90A"), exclusiveto, contract] */
                MIDL_INTERFACE("8A45CD0A-6323-44E0-A6F6-9F21F64DC90A")
                IPhoneLineWatcher : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Start(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Stop(void) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LineAdded(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LineAdded(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LineRemoved(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LineRemoved(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LineUpdated(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LineUpdated(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_EnumerationCompleted(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_EnumerationCompleted(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Stopped(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Stopped(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneLineWatcherStatus * status
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineWatcher=_uuidof(IPhoneLineWatcher);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineWatcherEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineWatcherEventArgs[] = L"Windows.ApplicationModel.Calls.IPhoneLineWatcherEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("D07C753E-9E12-4A37-82B7-AD535DAD6A67"), exclusiveto, contract] */
                MIDL_INTERFACE("D07C753E-9E12-4A37-82B7-AD535DAD6A67")
                IPhoneLineWatcherEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LineId(
                        /* [retval, out] */__RPC__out GUID * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneLineWatcherEventArgs=_uuidof(IPhoneLineWatcherEventArgs);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneVoicemail
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneVoicemail
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneVoicemail[] = L"Windows.ApplicationModel.Calls.IPhoneVoicemail";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("C9CE77F6-6E9F-3A8B-B727-6E0CF6998224"), exclusiveto, contract] */
                MIDL_INTERFACE("C9CE77F6-6E9F-3A8B-B727-6E0CF6998224")
                IPhoneVoicemail : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Number(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MessageCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Type(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::PhoneVoicemailType * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DialVoicemailAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IPhoneVoicemail=_uuidof(IPhoneVoicemail);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("4F118BCF-E8EF-4434-9C5F-A8D893FAFE79"), exclusiveto, contract] */
                MIDL_INTERFACE("4F118BCF-E8EF-4434-9C5F-A8D893FAFE79")
                IVoipCallCoordinator : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE ReserveCallResourcesAsync(
                        /* [in] */__RPC__in HSTRING taskEntryPoint,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * * operation
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_MuteStateChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs * muteChangeHandler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_MuteStateChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestNewIncomingCall(
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING contactNumber,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * contactImage,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * brandingImage,
                        /* [in] */__RPC__in HSTRING callDetails,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * ringtone,
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia media,
                        /* [in] */ABI::Windows::Foundation::TimeSpan ringTimeout,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestNewOutgoingCall(
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia media,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NotifyMuted(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NotifyUnmuted(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestOutgoingUpgradeToVideoCall(
                        /* [in] */GUID callUpgradeGuid,
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestIncomingUpgradeToVideoCall(
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING contactNumber,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * contactImage,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * brandingImage,
                        /* [in] */__RPC__in HSTRING callDetails,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * ringtone,
                        /* [in] */ABI::Windows::Foundation::TimeSpan ringTimeout,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TerminateCellularCall(
                        /* [in] */GUID callUpgradeGuid
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CancelUpgrade(
                        /* [in] */GUID callUpgradeGuid
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipCallCoordinator=_uuidof(IVoipCallCoordinator);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator2[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("BEB4A9F3-C704-4234-89CE-E88CC0D28FBE"), exclusiveto, contract] */
                MIDL_INTERFACE("BEB4A9F3-C704-4234-89CE-E88CC0D28FBE")
                IVoipCallCoordinator2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE SetupNewAcceptedCall(
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING contactNumber,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia media,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipCallCoordinator2=_uuidof(IVoipCallCoordinator2);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator3
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator3[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator3";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("338D0CBF-9B55-4021-87CA-E64B9BD666C7"), exclusiveto, contract] */
                MIDL_INTERFACE("338D0CBF-9B55-4021-87CA-E64B9BD666C7")
                IVoipCallCoordinator3 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE RequestNewAppInitiatedCall(
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING contactNumber,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia media,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestNewIncomingCallWithContactRemoteId(
                        /* [in] */__RPC__in HSTRING context,
                        /* [in] */__RPC__in HSTRING contactName,
                        /* [in] */__RPC__in HSTRING contactNumber,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * contactImage,
                        /* [in] */__RPC__in HSTRING serviceName,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * brandingImage,
                        /* [in] */__RPC__in HSTRING callDetails,
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * ringtone,
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia media,
                        /* [in] */ABI::Windows::Foundation::TimeSpan ringTimeout,
                        /* [in] */__RPC__in HSTRING contactRemoteId,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipPhoneCall * * call
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipCallCoordinator3=_uuidof(IVoipCallCoordinator3);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator4
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator4[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator4";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("83737239-9311-468F-BB49-47E0DFB5D93E"), exclusiveto, contract] */
                MIDL_INTERFACE("83737239-9311-468F-BB49-47E0DFB5D93E")
                IVoipCallCoordinator4 : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE ReserveOneProcessCallResourcesAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipCallCoordinator4=_uuidof(IVoipCallCoordinator4);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinatorStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinatorStatics[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinatorStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("7F5D1F2B-E04A-4D10-B31A-A55C922CC2FB"), exclusiveto, contract] */
                MIDL_INTERFACE("7F5D1F2B-E04A-4D10-B31A-A55C922CC2FB")
                IVoipCallCoordinatorStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDefault(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Calls::IVoipCallCoordinator * * coordinator
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipCallCoordinatorStatics=_uuidof(IVoipCallCoordinatorStatics);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipPhoneCall
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipPhoneCall[] = L"Windows.ApplicationModel.Calls.IVoipPhoneCall";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("6CF1F19A-7794-4A5A-8C68-AE87947A6990"), exclusiveto, contract] */
                MIDL_INTERFACE("6CF1F19A-7794-4A5A-8C68-AE87947A6990")
                IVoipPhoneCall : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_EndRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_EndRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_HoldRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_HoldRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ResumeRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ResumeRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_AnswerRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs * acceptHandler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_AnswerRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_RejectRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs * rejectHandler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_RejectRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NotifyCallHeld(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NotifyCallActive(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NotifyCallEnded(void) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContactName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ContactName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StartTime(
                        /* [in] */ABI::Windows::Foundation::DateTime value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CallMedia(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_CallMedia(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NotifyCallReady(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipPhoneCall=_uuidof(IVoipPhoneCall);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipPhoneCall2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipPhoneCall
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipPhoneCall2[] = L"Windows.ApplicationModel.Calls.IVoipPhoneCall2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("741B46E1-245F-41F3-9399-3141D25B52E3"), exclusiveto, contract] */
                MIDL_INTERFACE("741B46E1-245F-41F3-9399-3141D25B52E3")
                IVoipPhoneCall2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE TryShowAppUI(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipPhoneCall2=_uuidof(IVoipPhoneCall2);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipPhoneCall3
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipPhoneCall2
 *     Windows.ApplicationModel.Calls.IVoipPhoneCall
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipPhoneCall3[] = L"Windows.ApplicationModel.Calls.IVoipPhoneCall3";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Calls {
                /* [object, uuid("0D891522-E258-4AA9-907A-1AA413C25523"), exclusiveto, contract] */
                MIDL_INTERFACE("0D891522-E258-4AA9-907A-1AA413C25523")
                IVoipPhoneCall3 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE NotifyCallAccepted(
                        /* [in] */ABI::Windows::ApplicationModel::Calls::VoipPhoneCallMedia media
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IVoipPhoneCall3=_uuidof(IVoipPhoneCall3);
                
            } /* Calls */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.ApplicationModel.Calls.CallAnswerEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ICallAnswerEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_CallAnswerEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_CallAnswerEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_CallAnswerEventArgs[] = L"Windows.ApplicationModel.Calls.CallAnswerEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.CallRejectEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ICallRejectEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_CallRejectEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_CallRejectEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_CallRejectEventArgs[] = L"Windows.ApplicationModel.Calls.CallRejectEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.CallStateChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ICallStateChangeEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_CallStateChangeEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_CallStateChangeEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_CallStateChangeEventArgs[] = L"Windows.ApplicationModel.Calls.CallStateChangeEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.LockScreenCallEndCallDeferral
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ILockScreenCallEndCallDeferral ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndCallDeferral_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndCallDeferral_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_LockScreenCallEndCallDeferral[] = L"Windows.ApplicationModel.Calls.LockScreenCallEndCallDeferral";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ILockScreenCallEndRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_LockScreenCallEndRequestedEventArgs[] = L"Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.LockScreenCallUI
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ILockScreenCallUI ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallUI_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallUI_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_LockScreenCallUI[] = L"Windows.ApplicationModel.Calls.LockScreenCallUI";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.MuteChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IMuteChangeEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_MuteChangeEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_MuteChangeEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_MuteChangeEventArgs[] = L"Windows.ApplicationModel.Calls.MuteChangeEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallBlocking
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallBlockingStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallBlocking_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallBlocking_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallBlocking[] = L"Windows.ApplicationModel.Calls.PhoneCallBlocking";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntry
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntry ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntry_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntry_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntry[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntry";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Type can be activated via the Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddressFactory interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddress ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryAddress_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryAddress_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryAddress[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryQueryOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryQueryOptions_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryQueryOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryQueryOptions[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryOptions";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntryReader
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryReader ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryReader_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryReader_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryReader[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntryReader";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics2 interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryManager[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryManagerForUser
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerForUser ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManagerForUser_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManagerForUser_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryManagerForUser[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryManagerForUser";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryStore
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryStore ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryStore_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryStore_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryStore[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryStore";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallManager
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallManagerStatics2 interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallManagerStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallManager[] = L"Windows.ApplicationModel.Calls.PhoneCallManager";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallStore
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallStore ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallStore_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallStore_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallStore[] = L"Windows.ApplicationModel.Calls.PhoneCallStore";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilities ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilities_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilities_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilities[] = L"Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallVideoCapabilitiesManager
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilitiesManagerStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilitiesManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilitiesManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilitiesManager[] = L"Windows.ApplicationModel.Calls.PhoneCallVideoCapabilitiesManager";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneDialOptions
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneDialOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneDialOptions_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneDialOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneDialOptions[] = L"Windows.ApplicationModel.Calls.PhoneDialOptions";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLine
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneLineStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLine ** Default Interface **
 *    Windows.ApplicationModel.Calls.IPhoneLine2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLine_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLine_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLine[] = L"Windows.ApplicationModel.Calls.PhoneLine";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineCellularDetails
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineCellularDetails ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineCellularDetails_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineCellularDetails_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineCellularDetails[] = L"Windows.ApplicationModel.Calls.PhoneLineCellularDetails";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineConfiguration
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineConfiguration_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineConfiguration[] = L"Windows.ApplicationModel.Calls.PhoneLineConfiguration";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineTransportDevice
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneLineTransportDeviceStatics interface starting with version 5.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineTransportDevice ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineTransportDevice_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineTransportDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineTransportDevice[] = L"Windows.ApplicationModel.Calls.PhoneLineTransportDevice";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineWatcher
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineWatcher ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcher_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcher_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineWatcher[] = L"Windows.ApplicationModel.Calls.PhoneLineWatcher";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineWatcherEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcherEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcherEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineWatcherEventArgs[] = L"Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneVoicemail
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneVoicemail ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneVoicemail_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneVoicemail_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneVoicemail[] = L"Windows.ApplicationModel.Calls.PhoneVoicemail";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IVoipCallCoordinatorStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsVoipContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator ** Default Interface **
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator2
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator3
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator4
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipCallCoordinator_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipCallCoordinator_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_VoipCallCoordinator[] = L"Windows.ApplicationModel.Calls.VoipCallCoordinator";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IVoipPhoneCall ** Default Interface **
 *    Windows.ApplicationModel.Calls.IVoipPhoneCall2
 *    Windows.ApplicationModel.Calls.IVoipPhoneCall3
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipPhoneCall_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipPhoneCall_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_VoipPhoneCall[] = L"Windows.ApplicationModel.Calls.VoipPhoneCall";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3;

#endif // ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef struct __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef  struct __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry **first);

    END_INTERFACE
} __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef struct __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
            /* [in] */ __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStoreVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStoreVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStoreVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStoreVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStoreVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStoreVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStoreVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStoreVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStoreVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStoreVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallStore **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStoreVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStoreVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilitiesVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilitiesVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilitiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilitiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilitiesVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilitiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLineVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLineVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLineVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLineVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CPhoneLine **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLineVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLineVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallResourceReservationStatus;
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatusVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * This, /* [retval][out] */ __RPC__out enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallResourceReservationStatus *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatusVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus_INTERFACE_DEFINED__



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry;

typedef struct __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * This, /* [retval][out] */ __RPC__out __FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * *results);
    END_INTERFACE
} __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl;

interface __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry
{
    CONST_VTBL struct __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000



#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#if !defined(____FIIterator_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterator_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterator_1_HSTRING __FIIterator_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_HSTRING;

typedef struct __FIIterator_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out HSTRING *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_HSTRING * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_HSTRINGVtbl;

interface __FIIterator_1_HSTRING
{
    CONST_VTBL struct __FIIterator_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_HSTRING_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_HSTRING_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_HSTRING_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_HSTRING_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterable_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterable_1_HSTRING __FIIterable_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_HSTRING;

typedef  struct __FIIterable_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_HSTRING * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_HSTRING **first);

    END_INTERFACE
} __FIIterable_1_HSTRINGVtbl;

interface __FIIterable_1_HSTRING
{
    CONST_VTBL struct __FIIterable_1_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_HSTRING_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_HSTRING_INTERFACE_DEFINED__


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


struct __x_ABI_CWindows_CFoundation_CTimeSpan;

#if !defined(____FIReference_1_Windows__CFoundation__CTimeSpan_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CFoundation__CTimeSpan_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CFoundation__CTimeSpan __FIReference_1_Windows__CFoundation__CTimeSpan;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CFoundation__CTimeSpan;

typedef struct __FIReference_1_Windows__CFoundation__CTimeSpanVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CFoundation__CTimeSpan * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CFoundation_CTimeSpan *value);
    END_INTERFACE
} __FIReference_1_Windows__CFoundation__CTimeSpanVtbl;

interface __FIReference_1_Windows__CFoundation__CTimeSpan
{
    CONST_VTBL struct __FIReference_1_Windows__CFoundation__CTimeSpanVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CFoundation__CTimeSpan_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CFoundation__CTimeSpan_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CFoundation__CTimeSpan_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CFoundation__CTimeSpan_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CFoundation__CTimeSpan_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CFoundation__CTimeSpan_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CFoundation__CTimeSpan_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CFoundation__CTimeSpan_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIVectorView_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_HSTRING __FIVectorView_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_HSTRING;

typedef struct __FIVectorView_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_HSTRING * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_HSTRING * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out HSTRING *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_HSTRING * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_HSTRING * This,
            /* [in] */ HSTRING item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_HSTRING * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_HSTRINGVtbl;

interface __FIVectorView_1_HSTRING
{
    CONST_VTBL struct __FIVectorView_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_HSTRING_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_HSTRING_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_HSTRING_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_HSTRING_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIVector_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIVector_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIVector_1_HSTRING __FIVector_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_HSTRING;

typedef struct __FIVector_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_HSTRING * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_HSTRING * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt HSTRING *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_HSTRING * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_HSTRING **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_HSTRING * This,
        /* [in] */ __RPC__in HSTRING item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_HSTRING * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in HSTRING item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_HSTRING * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in HSTRING item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_HSTRING * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_HSTRING * This, /* [in] */ __RPC__in HSTRING item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_HSTRING * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_HSTRING * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) HSTRING *value);

    END_INTERFACE
} __FIVector_1_HSTRINGVtbl;

interface __FIVector_1_HSTRING
{
    CONST_VTBL struct __FIVector_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_HSTRING_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_HSTRING_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_HSTRING_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_HSTRING_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_HSTRING_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_HSTRING_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_HSTRING_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_HSTRING_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_HSTRING_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_HSTRING_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_HSTRING_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_HSTRING_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_HSTRING_INTERFACE_DEFINED__


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



#if !defined(____FIEventHandler_1_IInspectable_INTERFACE_DEFINED__)
#define ____FIEventHandler_1_IInspectable_INTERFACE_DEFINED__

typedef interface __FIEventHandler_1_IInspectable __FIEventHandler_1_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIEventHandler_1_IInspectable;

typedef struct __FIEventHandler_1_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIEventHandler_1_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIEventHandler_1_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIEventHandler_1_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIEventHandler_1_IInspectable * This,/* [in] */ __RPC__in_opt IInspectable *sender,/* [in] */ __RPC__in_opt IInspectable * *e);
    END_INTERFACE
} __FIEventHandler_1_IInspectableVtbl;

interface __FIEventHandler_1_IInspectable
{
    CONST_VTBL struct __FIEventHandler_1_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIEventHandler_1_IInspectable_QueryInterface(This,riid,ppvObject)	\
        ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIEventHandler_1_IInspectable_AddRef(This)	\
        ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIEventHandler_1_IInspectable_Release(This)	\
        ( (This)->lpVtbl -> Release(This) ) 

#define __FIEventHandler_1_IInspectable_Invoke(This,sender,e)	\
        ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */


#endif // ____FIEventHandler_1_IInspectable_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperationCompletedHandler_1_GUID_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_GUID_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_GUID __FIAsyncOperationCompletedHandler_1_GUID;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_GUID;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_GUID __FIAsyncOperation_1_GUID;

typedef struct __FIAsyncOperationCompletedHandler_1_GUIDVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_GUID * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_GUID * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_GUID * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_GUID * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_GUID *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_GUIDVtbl;

interface __FIAsyncOperationCompletedHandler_1_GUID
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_GUIDVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_GUID_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_GUID_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_GUID_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_GUID_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_GUID_INTERFACE_DEFINED__


#if !defined(____FIAsyncOperation_1_GUID_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_GUID_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_GUID __FIAsyncOperation_1_GUID;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_GUID;

typedef struct __FIAsyncOperation_1_GUIDVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_GUID * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_GUID * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_GUID * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_GUID * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_GUID * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_GUID * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_GUID * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_GUID *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_GUID * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_GUID **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_GUID * This, /* [retval][out] */ __RPC__out GUID *results);
    END_INTERFACE
} __FIAsyncOperation_1_GUIDVtbl;

interface __FIAsyncOperation_1_GUID
{
    CONST_VTBL struct __FIAsyncOperation_1_GUIDVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_GUID_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_GUID_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_GUID_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_GUID_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_GUID_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_GUID_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_GUID_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_GUID_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_GUID_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_GUID_INTERFACE_DEFINED__



#if !defined(____FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIKeyValuePair_2_HSTRING_IInspectable __FIKeyValuePair_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIKeyValuePair_2_HSTRING_IInspectable;

typedef struct __FIKeyValuePair_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Key )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out HSTRING *key);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__deref_out_opt IInspectable * *value);
    END_INTERFACE
} __FIKeyValuePair_2_HSTRING_IInspectableVtbl;

interface __FIKeyValuePair_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIKeyValuePair_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIKeyValuePair_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIKeyValuePair_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIKeyValuePair_2_HSTRING_IInspectable_get_Key(This,key)	\
    ( (This)->lpVtbl -> get_Key(This,key) ) 

#define __FIKeyValuePair_2_HSTRING_IInspectable_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable;

typedef struct __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out __FIKeyValuePair_2_HSTRING_IInspectable * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __FIKeyValuePair_2_HSTRING_IInspectable * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl;

interface __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable;

typedef  struct __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___FIKeyValuePair_2_HSTRING_IInspectable **first);

    END_INTERFACE
} __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl;

interface __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___FIKeyValuePair_2_HSTRING_IInspectable_INTERFACE_DEFINED__



#if !defined(____FIMapView_2_HSTRING_IInspectable_INTERFACE_DEFINED__)
#define ____FIMapView_2_HSTRING_IInspectable_INTERFACE_DEFINED__

typedef interface __FIMapView_2_HSTRING_IInspectable __FIMapView_2_HSTRING_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMapView_2_HSTRING_IInspectable;

typedef struct __FIMapView_2_HSTRING_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,/* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,
        /* [in] */ __RPC__in HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt IInspectable * *value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This, /* [in] */ __RPC__in HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *Split )(__RPC__in __FIMapView_2_HSTRING_IInspectable * This,/* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable **firstPartition,
        /* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable **secondPartition);
    END_INTERFACE
} __FIMapView_2_HSTRING_IInspectableVtbl;

interface __FIMapView_2_HSTRING_IInspectable
{
    CONST_VTBL struct __FIMapView_2_HSTRING_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMapView_2_HSTRING_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIMapView_2_HSTRING_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIMapView_2_HSTRING_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIMapView_2_HSTRING_IInspectable_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIMapView_2_HSTRING_IInspectable_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIMapView_2_HSTRING_IInspectable_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIMapView_2_HSTRING_IInspectable_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 
#define __FIMapView_2_HSTRING_IInspectable_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 
#define __FIMapView_2_HSTRING_IInspectable_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 
#define __FIMapView_2_HSTRING_IInspectable_Split(This,firstPartition,secondPartition)	\
    ( (This)->lpVtbl -> Split(This,firstPartition,secondPartition) ) 
#endif /* COBJMACROS */


#endif // ____FIMapView_2_HSTRING_IInspectable_INTERFACE_DEFINED__


enum __x_ABI_CWindows_CDevices_CEnumeration_CDeviceAccessStatus;
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatusVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_INTERFACE_DEFINED__



#if !defined(____FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus;

typedef struct __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * This, /* [retval][out] */ __RPC__out enum __x_ABI_CWindows_CDevices_CEnumeration_CDeviceAccessStatus *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatusVtbl;

interface __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus_INTERFACE_DEFINED__



#ifndef ____x_ABI_CWindows_CApplicationModel_CContacts_CIContact_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CContacts_CIContact_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CContacts_CIContact __x_ABI_CWindows_CApplicationModel_CContacts_CIContact;

#endif // ____x_ABI_CWindows_CApplicationModel_CContacts_CIContact_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone __x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone;

#endif // ____x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CDevices_CEnumeration_CDeviceAccessStatus __x_ABI_CWindows_CDevices_CEnumeration_CDeviceAccessStatus;





typedef struct __x_ABI_CWindows_CFoundation_CDateTime __x_ABI_CWindows_CFoundation_CDateTime;

#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIAsyncAction __x_ABI_CWindows_CFoundation_CIAsyncAction;

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;


#ifndef ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIUriRuntimeClass __x_ABI_CWindows_CFoundation_CIUriRuntimeClass;

#endif // ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CIUser __x_ABI_CWindows_CSystem_CIUser;

#endif // ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__





typedef struct __x_ABI_CWindows_CUI_CColor __x_ABI_CWindows_CUI_CColor;







typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CCellularDtmfMode __x_ABI_CWindows_CApplicationModel_CCalls_CCellularDtmfMode;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneAudioRoutingEndpoint __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneAudioRoutingEndpoint;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryMedia __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryMedia;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryOtherAppReadAccess __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryOtherAppReadAccess;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryQueryDesiredMedia __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryQueryDesiredMedia;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryRawAddressKind __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryRawAddressKind;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistorySourceIdKind __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistorySourceIdKind;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryStoreAccessType __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryStoreAccessType;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallMedia __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallMedia;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineNetworkOperatorDisplayTextLocation __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineNetworkOperatorDisplayTextLocation;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineTransport __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineTransport;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineWatcherStatus __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineWatcherStatus;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneNetworkState __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneNetworkState;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneSimState __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneSimState;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneVoicemailType __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneVoicemailType;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallRejectReason __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallRejectReason;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallResourceReservationStatus __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallResourceReservationStatus;


typedef enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallState __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallState;

















































































/*
 *
 * Struct Windows.ApplicationModel.Calls.CellularDtmfMode
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CCellularDtmfMode
{
    CellularDtmfMode_Continuous = 0,
    CellularDtmfMode_Burst = 1,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneAudioRoutingEndpoint
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneAudioRoutingEndpoint
{
    PhoneAudioRoutingEndpoint_Default = 0,
    PhoneAudioRoutingEndpoint_Bluetooth = 1,
    PhoneAudioRoutingEndpoint_Speakerphone = 2,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryMedia
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryMedia
{
    PhoneCallHistoryEntryMedia_Audio = 0,
    PhoneCallHistoryEntryMedia_Video = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryOtherAppReadAccess
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryOtherAppReadAccess
{
    PhoneCallHistoryEntryOtherAppReadAccess_Full = 0,
    PhoneCallHistoryEntryOtherAppReadAccess_SystemOnly = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryDesiredMedia
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryQueryDesiredMedia
{
    PhoneCallHistoryEntryQueryDesiredMedia_None = 0,
    PhoneCallHistoryEntryQueryDesiredMedia_Audio = 0x1,
    PhoneCallHistoryEntryQueryDesiredMedia_Video = 0x2,
    PhoneCallHistoryEntryQueryDesiredMedia_All = 0xffffffff,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryEntryRawAddressKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryRawAddressKind
{
    PhoneCallHistoryEntryRawAddressKind_PhoneNumber = 0,
    PhoneCallHistoryEntryRawAddressKind_Custom = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistorySourceIdKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistorySourceIdKind
{
    PhoneCallHistorySourceIdKind_CellularPhoneLineId = 0,
    PhoneCallHistorySourceIdKind_PackageFamilyName = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallHistoryStoreAccessType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryStoreAccessType
{
    PhoneCallHistoryStoreAccessType_AppEntriesReadWrite = 0,
    PhoneCallHistoryStoreAccessType_AllEntriesLimitedReadWrite = 1,
    PhoneCallHistoryStoreAccessType_AllEntriesReadWrite = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneCallMedia
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallMedia
{
    PhoneCallMedia_Audio = 0,
    PhoneCallMedia_AudioAndVideo = 1,
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x40000
    
    PhoneCallMedia_AudioAndRealTimeText = 2,
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x40000
    
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneLineNetworkOperatorDisplayTextLocation
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineNetworkOperatorDisplayTextLocation
{
    PhoneLineNetworkOperatorDisplayTextLocation_Default = 0,
    PhoneLineNetworkOperatorDisplayTextLocation_Tile = 1,
    PhoneLineNetworkOperatorDisplayTextLocation_Dialer = 2,
    PhoneLineNetworkOperatorDisplayTextLocation_InCallUI = 3,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneLineTransport
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineTransport
{
    PhoneLineTransport_Cellular = 0,
    PhoneLineTransport_VoipApp = 1,
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
    
    PhoneLineTransport_Bluetooth = 2,
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
    
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneLineWatcherStatus
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineWatcherStatus
{
    PhoneLineWatcherStatus_Created = 0,
    PhoneLineWatcherStatus_Started = 1,
    PhoneLineWatcherStatus_EnumerationCompleted = 2,
    PhoneLineWatcherStatus_Stopped = 3,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneNetworkState
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneNetworkState
{
    PhoneNetworkState_Unknown = 0,
    PhoneNetworkState_NoSignal = 1,
    PhoneNetworkState_Deregistered = 2,
    PhoneNetworkState_Denied = 3,
    PhoneNetworkState_Searching = 4,
    PhoneNetworkState_Home = 5,
    PhoneNetworkState_RoamingInternational = 6,
    PhoneNetworkState_RoamingDomestic = 7,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneSimState
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneSimState
{
    PhoneSimState_Unknown = 0,
    PhoneSimState_PinNotRequired = 1,
    PhoneSimState_PinUnlocked = 2,
    PhoneSimState_PinLocked = 3,
    PhoneSimState_PukLocked = 4,
    PhoneSimState_NotInserted = 5,
    PhoneSimState_Invalid = 6,
    PhoneSimState_Disabled = 7,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.PhoneVoicemailType
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneVoicemailType
{
    PhoneVoicemailType_None = 0,
    PhoneVoicemailType_Traditional = 1,
    PhoneVoicemailType_Visual = 2,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallMedia
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia
{
    VoipPhoneCallMedia_None = 0,
    VoipPhoneCallMedia_Audio = 0x1,
    VoipPhoneCallMedia_Video = 0x2,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallRejectReason
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallRejectReason
{
    VoipPhoneCallRejectReason_UserIgnored = 0,
    VoipPhoneCallRejectReason_TimedOut = 1,
    VoipPhoneCallRejectReason_OtherIncomingCall = 2,
    VoipPhoneCallRejectReason_EmergencyCallExists = 3,
    VoipPhoneCallRejectReason_InvalidCallState = 4,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallResourceReservationStatus
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallResourceReservationStatus
{
    VoipPhoneCallResourceReservationStatus_Success = 0,
    VoipPhoneCallResourceReservationStatus_ResourcesNotAvailable = 1,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.ApplicationModel.Calls.VoipPhoneCallState
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 */

#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallState
{
    VoipPhoneCallState_Ended = 0,
    VoipPhoneCallState_Held = 1,
    VoipPhoneCallState_Active = 2,
    VoipPhoneCallState_Incoming = 3,
    VoipPhoneCallState_Outgoing = 4,
};
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ICallAnswerEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.CallAnswerEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ICallAnswerEventArgs[] = L"Windows.ApplicationModel.Calls.ICallAnswerEventArgs";
/* [object, uuid("FD789617-2DD7-4C8C-B2BD-95D17A5BB733"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AcceptedMedia )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_get_AcceptedMedia(This,value) \
    ( (This)->lpVtbl->get_AcceptedMedia(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallAnswerEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ICallRejectEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.CallRejectEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ICallRejectEventArgs[] = L"Windows.ApplicationModel.Calls.ICallRejectEventArgs";
/* [object, uuid("DA47FAD7-13D4-4D92-A1C2-B77811EE37EC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RejectReason )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallRejectReason * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_get_RejectReason(This,value) \
    ( (This)->lpVtbl->get_RejectReason(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallRejectEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ICallStateChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.CallStateChangeEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ICallStateChangeEventArgs[] = L"Windows.ApplicationModel.Calls.ICallStateChangeEventArgs";
/* [object, uuid("EAB2349E-66F5-47F9-9FB5-459C5198C720"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_State )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallState * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_get_State(This,value) \
    ( (This)->lpVtbl->get_State(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CICallStateChangeEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ILockScreenCallEndCallDeferral
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.LockScreenCallEndCallDeferral
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ILockScreenCallEndCallDeferral[] = L"Windows.ApplicationModel.Calls.ILockScreenCallEndCallDeferral";
/* [object, uuid("2DD7ED0D-98ED-4041-9632-50FF812B773F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferralVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Complete )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferralVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferralVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_Complete(This) \
    ( (This)->lpVtbl->Complete(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ILockScreenCallEndRequestedEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ILockScreenCallEndRequestedEventArgs[] = L"Windows.ApplicationModel.Calls.ILockScreenCallEndRequestedEventArgs";
/* [object, uuid("8190A363-6F27-46E9-AEB6-C0AE83E47DC7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndCallDeferral * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Deadline )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_GetDeferral(This,value) \
    ( (This)->lpVtbl->GetDeferral(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_get_Deadline(This,value) \
    ( (This)->lpVtbl->get_Deadline(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallEndRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.ILockScreenCallUI
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.LockScreenCallUI
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_ILockScreenCallUI[] = L"Windows.ApplicationModel.Calls.ILockScreenCallUI";
/* [object, uuid("C596FD8D-73C9-4A14-B021-EC1C50A3B727"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUIVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Dismiss )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_EndRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_Windows__CApplicationModel__CCalls__CLockScreenCallEndRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_EndRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Closed )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CLockScreenCallUI_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Closed )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CallTitle )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_CallTitle )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI * This,
        /* [in] */__RPC__in HSTRING value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUIVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUIVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_Dismiss(This) \
    ( (This)->lpVtbl->Dismiss(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_add_EndRequested(This,handler,token) \
    ( (This)->lpVtbl->add_EndRequested(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_remove_EndRequested(This,token) \
    ( (This)->lpVtbl->remove_EndRequested(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_add_Closed(This,handler,token) \
    ( (This)->lpVtbl->add_Closed(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_remove_Closed(This,token) \
    ( (This)->lpVtbl->remove_Closed(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_get_CallTitle(This,value) \
    ( (This)->lpVtbl->get_CallTitle(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_put_CallTitle(This,value) \
    ( (This)->lpVtbl->put_CallTitle(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CILockScreenCallUI_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IMuteChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.MuteChangeEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IMuteChangeEventArgs[] = L"Windows.ApplicationModel.Calls.IMuteChangeEventArgs";
/* [object, uuid("8585E159-0C41-432C-814D-C5F1FDF530BE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Muted )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_get_Muted(This,value) \
    ( (This)->lpVtbl->get_Muted(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIMuteChangeEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallBlockingStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallBlocking
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallBlockingStatics";
/* [object, uuid("19646F84-2B79-26F1-A46F-694BE043F313"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BlockUnknownNumbers )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BlockUnknownNumbers )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BlockPrivateNumbers )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BlockPrivateNumbers )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
        /* [in] */boolean value
        );
    HRESULT ( STDMETHODCALLTYPE *SetCallBlockingListAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * phoneNumberList,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_get_BlockUnknownNumbers(This,value) \
    ( (This)->lpVtbl->get_BlockUnknownNumbers(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_put_BlockUnknownNumbers(This,value) \
    ( (This)->lpVtbl->put_BlockUnknownNumbers(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_get_BlockPrivateNumbers(This,value) \
    ( (This)->lpVtbl->get_BlockPrivateNumbers(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_put_BlockPrivateNumbers(This,value) \
    ( (This)->lpVtbl->put_BlockPrivateNumbers(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_SetCallBlockingListAsync(This,phoneNumberList,result) \
    ( (This)->lpVtbl->SetCallBlockingListAsync(This,phoneNumberList,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallBlockingStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntry
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntry
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntry";
/* [object, uuid("FAB0E129-32A4-4B85-83D1-F90D8C23A857"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Address )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Address )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Duration )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CTimeSpan * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Duration )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CFoundation__CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsCallerIdBlocked )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsCallerIdBlocked )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsEmergency )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsEmergency )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsIncoming )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsIncoming )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsMissed )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsMissed )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRinging )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsRinging )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsSeen )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsSeen )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsSuppressed )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsSuppressed )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVoicemail )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsVoicemail )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Media )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryMedia * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Media )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryMedia value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OtherAppReadAccess )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryOtherAppReadAccess * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_OtherAppReadAccess )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryOtherAppReadAccess value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RemoteId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RemoteId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SourceDisplayName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SourceId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SourceId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SourceIdKind )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistorySourceIdKind * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SourceIdKind )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistorySourceIdKind value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartTime )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StartTime )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CDateTime value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_Address(This,value) \
    ( (This)->lpVtbl->get_Address(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_Address(This,value) \
    ( (This)->lpVtbl->put_Address(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_Duration(This,value) \
    ( (This)->lpVtbl->get_Duration(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_Duration(This,value) \
    ( (This)->lpVtbl->put_Duration(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsCallerIdBlocked(This,value) \
    ( (This)->lpVtbl->get_IsCallerIdBlocked(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsCallerIdBlocked(This,value) \
    ( (This)->lpVtbl->put_IsCallerIdBlocked(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsEmergency(This,value) \
    ( (This)->lpVtbl->get_IsEmergency(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsEmergency(This,value) \
    ( (This)->lpVtbl->put_IsEmergency(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsIncoming(This,value) \
    ( (This)->lpVtbl->get_IsIncoming(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsIncoming(This,value) \
    ( (This)->lpVtbl->put_IsIncoming(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsMissed(This,value) \
    ( (This)->lpVtbl->get_IsMissed(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsMissed(This,value) \
    ( (This)->lpVtbl->put_IsMissed(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsRinging(This,value) \
    ( (This)->lpVtbl->get_IsRinging(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsRinging(This,value) \
    ( (This)->lpVtbl->put_IsRinging(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsSeen(This,value) \
    ( (This)->lpVtbl->get_IsSeen(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsSeen(This,value) \
    ( (This)->lpVtbl->put_IsSeen(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsSuppressed(This,value) \
    ( (This)->lpVtbl->get_IsSuppressed(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsSuppressed(This,value) \
    ( (This)->lpVtbl->put_IsSuppressed(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_IsVoicemail(This,value) \
    ( (This)->lpVtbl->get_IsVoicemail(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_IsVoicemail(This,value) \
    ( (This)->lpVtbl->put_IsVoicemail(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_Media(This,value) \
    ( (This)->lpVtbl->get_Media(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_Media(This,value) \
    ( (This)->lpVtbl->put_Media(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_OtherAppReadAccess(This,value) \
    ( (This)->lpVtbl->get_OtherAppReadAccess(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_OtherAppReadAccess(This,value) \
    ( (This)->lpVtbl->put_OtherAppReadAccess(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_RemoteId(This,value) \
    ( (This)->lpVtbl->get_RemoteId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_RemoteId(This,value) \
    ( (This)->lpVtbl->put_RemoteId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_SourceDisplayName(This,value) \
    ( (This)->lpVtbl->get_SourceDisplayName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_SourceId(This,value) \
    ( (This)->lpVtbl->get_SourceId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_SourceId(This,value) \
    ( (This)->lpVtbl->put_SourceId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_SourceIdKind(This,value) \
    ( (This)->lpVtbl->get_SourceIdKind(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_SourceIdKind(This,value) \
    ( (This)->lpVtbl->put_SourceIdKind(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_get_StartTime(This,value) \
    ( (This)->lpVtbl->get_StartTime(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_put_StartTime(This,value) \
    ( (This)->lpVtbl->put_StartTime(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddress
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddress";
/* [object, uuid("30F159DA-3955-4042-84E6-66EEBF82E67F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContactId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ContactId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DisplayName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawAddress )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RawAddress )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawAddressKind )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryRawAddressKind * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RawAddressKind )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryRawAddressKind value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_get_ContactId(This,value) \
    ( (This)->lpVtbl->get_ContactId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_put_ContactId(This,value) \
    ( (This)->lpVtbl->put_ContactId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_put_DisplayName(This,value) \
    ( (This)->lpVtbl->put_DisplayName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_get_RawAddress(This,value) \
    ( (This)->lpVtbl->get_RawAddress(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_put_RawAddress(This,value) \
    ( (This)->lpVtbl->put_RawAddress(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_get_RawAddressKind(This,value) \
    ( (This)->lpVtbl->get_RawAddressKind(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_put_RawAddressKind(This,value) \
    ( (This)->lpVtbl->put_RawAddressKind(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddressFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddressFactory[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddressFactory";
/* [object, uuid("FB0FADBA-C7F0-4BB6-9F6B-BA5D73209ACA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory * This,
        /* [in] */__RPC__in HSTRING rawAddress,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryRawAddressKind rawAddressKind,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddress * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactoryVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_Create(This,rawAddress,rawAddressKind,result) \
    ( (This)->lpVtbl->Create(This,rawAddress,rawAddressKind,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryAddressFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryQueryOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryOptions
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryQueryOptions[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryQueryOptions";
/* [object, uuid("9C5FE15C-8BED-40CA-B06E-C4CA8EAE5C87"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptionsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DesiredMedia )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryQueryDesiredMedia * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DesiredMedia )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryEntryQueryDesiredMedia value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SourceIds )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_HSTRING * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptionsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptionsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_get_DesiredMedia(This,value) \
    ( (This)->lpVtbl->get_DesiredMedia(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_put_DesiredMedia(This,value) \
    ( (This)->lpVtbl->put_DesiredMedia(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_get_SourceIds(This,value) \
    ( (This)->lpVtbl->get_SourceIds(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryReader
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryEntryReader
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryReader[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryReader";
/* [object, uuid("61ECE4BE-8D86-479F-8404-A9846920FEE6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReaderVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ReadBatchAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReaderVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReaderVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_ReadBatchAsync(This,result) \
    ( (This)->lpVtbl->ReadBatchAsync(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerForUser
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryManagerForUser
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerForUser[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerForUser";
/* [object, uuid("D925C523-F55F-4353-9DB4-0205A5265A55"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUserVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *RequestStoreAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryStoreAccessType accessType,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_User )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSystem_CIUser * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUserVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUserVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_RequestStoreAsync(This,accessType,result) \
    ( (This)->lpVtbl->RequestStoreAsync(This,accessType,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_get_User(This,value) \
    ( (This)->lpVtbl->get_User(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics";
/* [object, uuid("F5A6DA39-B31F-4F45-AC8E-1B08893C1B50"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *RequestStoreAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallHistoryStoreAccessType accessType,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryStore * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_RequestStoreAsync(This,accessType,result) \
    ( (This)->lpVtbl->RequestStoreAsync(This,accessType,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerStatics2[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics2";
/* [object, uuid("EFD474F0-A2DB-4188-9E92-BC3CFA6813CF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForUser )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSystem_CIUser * user,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerForUser * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_GetForUser(This,user,result) \
    ( (This)->lpVtbl->GetForUser(This,user,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryManagerStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallHistoryStore
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallHistoryStore
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore[] = L"Windows.ApplicationModel.Calls.IPhoneCallHistoryStore";
/* [object, uuid("2F907DB8-B40E-422B-8545-CB1910A61C52"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStoreVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetEntryAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in HSTRING callHistoryEntryId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *GetEntryReader )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *GetEntryReaderWithOptions )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryQueryOptions * queryOptions,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntryReader * * result
        );
    HRESULT ( STDMETHODCALLTYPE *SaveEntryAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * callHistoryEntry,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    HRESULT ( STDMETHODCALLTYPE *DeleteEntryAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * callHistoryEntry,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    HRESULT ( STDMETHODCALLTYPE *DeleteEntriesAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * callHistoryEntries,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    HRESULT ( STDMETHODCALLTYPE *MarkEntryAsSeenAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryEntry * callHistoryEntry,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    HRESULT ( STDMETHODCALLTYPE *MarkEntriesAsSeenAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CApplicationModel__CCalls__CPhoneCallHistoryEntry * callHistoryEntries,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetUnseenCountAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_UINT32 * * result
        );
    HRESULT ( STDMETHODCALLTYPE *MarkAllAsSeenAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetSourcesUnseenCountAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * sourceIds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_UINT32 * * result
        );
    HRESULT ( STDMETHODCALLTYPE *MarkSourcesAsSeenAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * sourceIds,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStoreVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStoreVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetEntryAsync(This,callHistoryEntryId,result) \
    ( (This)->lpVtbl->GetEntryAsync(This,callHistoryEntryId,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetEntryReader(This,result) \
    ( (This)->lpVtbl->GetEntryReader(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetEntryReaderWithOptions(This,queryOptions,result) \
    ( (This)->lpVtbl->GetEntryReaderWithOptions(This,queryOptions,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_SaveEntryAsync(This,callHistoryEntry,result) \
    ( (This)->lpVtbl->SaveEntryAsync(This,callHistoryEntry,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_DeleteEntryAsync(This,callHistoryEntry,result) \
    ( (This)->lpVtbl->DeleteEntryAsync(This,callHistoryEntry,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_DeleteEntriesAsync(This,callHistoryEntries,result) \
    ( (This)->lpVtbl->DeleteEntriesAsync(This,callHistoryEntries,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_MarkEntryAsSeenAsync(This,callHistoryEntry,result) \
    ( (This)->lpVtbl->MarkEntryAsSeenAsync(This,callHistoryEntry,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_MarkEntriesAsSeenAsync(This,callHistoryEntries,result) \
    ( (This)->lpVtbl->MarkEntriesAsSeenAsync(This,callHistoryEntries,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetUnseenCountAsync(This,result) \
    ( (This)->lpVtbl->GetUnseenCountAsync(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_MarkAllAsSeenAsync(This,result) \
    ( (This)->lpVtbl->MarkAllAsSeenAsync(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_GetSourcesUnseenCountAsync(This,sourceIds,result) \
    ( (This)->lpVtbl->GetSourcesUnseenCountAsync(This,sourceIds,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_MarkSourcesAsSeenAsync(This,sourceIds,result) \
    ( (This)->lpVtbl->MarkSourcesAsSeenAsync(This,sourceIds,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallHistoryStore_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallManagerStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallManager
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallManagerStatics";
/* [object, uuid("60EDAC78-78A6-4872-A3EF-98325EC8B843"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ShowPhoneCallUI )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics * This,
        /* [in] */__RPC__in HSTRING phoneNumber,
        /* [in] */__RPC__in HSTRING displayName
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_ShowPhoneCallUI(This,phoneNumber,displayName) \
    ( (This)->lpVtbl->ShowPhoneCallUI(This,phoneNumber,displayName) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallManagerStatics2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallManager
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2[] = L"Windows.ApplicationModel.Calls.IPhoneCallManagerStatics2";
/* [object, uuid("C7E3C8BC-2370-431C-98FD-43BE5F03086D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_CallStateChanged )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
        /* [in] */__RPC__in_opt __FIEventHandler_1_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_CallStateChanged )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsCallActive )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsCallIncoming )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *ShowPhoneCallSettingsUI )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This
        );
    HRESULT ( STDMETHODCALLTYPE *RequestStoreAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2 * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallStore * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_add_CallStateChanged(This,handler,token) \
    ( (This)->lpVtbl->add_CallStateChanged(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_remove_CallStateChanged(This,token) \
    ( (This)->lpVtbl->remove_CallStateChanged(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_get_IsCallActive(This,value) \
    ( (This)->lpVtbl->get_IsCallActive(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_get_IsCallIncoming(This,value) \
    ( (This)->lpVtbl->get_IsCallIncoming(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_ShowPhoneCallSettingsUI(This) \
    ( (This)->lpVtbl->ShowPhoneCallSettingsUI(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_RequestStoreAsync(This,result) \
    ( (This)->lpVtbl->RequestStoreAsync(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallManagerStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallStore
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallStore
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallStore[] = L"Windows.ApplicationModel.Calls.IPhoneCallStore";
/* [object, uuid("5F610748-18A6-4173-86D1-28BE9DC62DBA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStoreVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *IsEmergencyPhoneNumberAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
        /* [in] */__RPC__in HSTRING number,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetDefaultLineAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_GUID * * result
        );
    HRESULT ( STDMETHODCALLTYPE *RequestLineWatcher )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStoreVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStoreVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_IsEmergencyPhoneNumberAsync(This,number,result) \
    ( (This)->lpVtbl->IsEmergencyPhoneNumberAsync(This,number,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_GetDefaultLineAsync(This,result) \
    ( (This)->lpVtbl->GetDefaultLineAsync(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_RequestLineWatcher(This,result) \
    ( (This)->lpVtbl->RequestLineWatcher(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallStore_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilities
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallVideoCapabilities[] = L"Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilities";
/* [object, uuid("02382786-B16A-4FDB-BE3B-C4240E13AD0D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVideoCallingCapable )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * This,
        /* [retval, out] */__RPC__out boolean * pValue
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_get_IsVideoCallingCapable(This,pValue) \
    ( (This)->lpVtbl->get_IsVideoCallingCapable(This,pValue) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilitiesManagerStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneCallVideoCapabilitiesManager
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneCallVideoCapabilitiesManagerStatics[] = L"Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilitiesManagerStatics";
/* [object, uuid("F3C64B56-F00B-4A1C-A0C6-EE1910749CE7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetCapabilitiesAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics * This,
        /* [in] */__RPC__in HSTRING phoneNumber,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneCallVideoCapabilities * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_GetCapabilitiesAsync(This,phoneNumber,result) \
    ( (This)->lpVtbl->GetCapabilitiesAsync(This,phoneNumber,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilitiesManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneDialOptions
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneDialOptions
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneDialOptions[] = L"Windows.ApplicationModel.Calls.IPhoneDialOptions";
/* [object, uuid("B639C4B8-F06F-36CB-A863-823742B5F2D4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptionsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Number )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Number )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DisplayName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Contact )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CContacts_CIContact * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Contact )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CContacts_CIContact * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContactPhone )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ContactPhone )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CContacts_CIContactPhone * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Media )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallMedia * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Media )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneCallMedia value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AudioEndpoint )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneAudioRoutingEndpoint * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AudioEndpoint )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneAudioRoutingEndpoint value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptionsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptionsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_get_Number(This,value) \
    ( (This)->lpVtbl->get_Number(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_put_Number(This,value) \
    ( (This)->lpVtbl->put_Number(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_put_DisplayName(This,value) \
    ( (This)->lpVtbl->put_DisplayName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_get_Contact(This,value) \
    ( (This)->lpVtbl->get_Contact(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_put_Contact(This,value) \
    ( (This)->lpVtbl->put_Contact(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_get_ContactPhone(This,value) \
    ( (This)->lpVtbl->get_ContactPhone(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_put_ContactPhone(This,value) \
    ( (This)->lpVtbl->put_ContactPhone(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_get_Media(This,value) \
    ( (This)->lpVtbl->get_Media(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_put_Media(This,value) \
    ( (This)->lpVtbl->put_Media(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_get_AudioEndpoint(This,value) \
    ( (This)->lpVtbl->get_AudioEndpoint(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_put_AudioEndpoint(This,value) \
    ( (This)->lpVtbl->put_AudioEndpoint(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLine
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLine
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLine[] = L"Windows.ApplicationModel.Calls.IPhoneLine";
/* [object, uuid("27C66F30-6A69-34CA-A2BA-65302530C311"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LineChanged )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLine_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LineChanged )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__out GUID * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayColor )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NetworkState )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneNetworkState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Voicemail )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NetworkName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CellularDetails )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Transport )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineTransport * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanDial )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SupportsTile )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_VideoCallingCapabilities )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneCallVideoCapabilities * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LineConfiguration )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * * value
        );
    HRESULT ( STDMETHODCALLTYPE *IsImmediateDialNumberAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [in] */__RPC__in HSTRING number,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * result
        );
    HRESULT ( STDMETHODCALLTYPE *Dial )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [in] */__RPC__in HSTRING number,
        /* [in] */__RPC__in HSTRING displayName
        );
    HRESULT ( STDMETHODCALLTYPE *DialWithOptions )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneDialOptions * options
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_add_LineChanged(This,handler,token) \
    ( (This)->lpVtbl->add_LineChanged(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_remove_LineChanged(This,token) \
    ( (This)->lpVtbl->remove_LineChanged(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_DisplayColor(This,value) \
    ( (This)->lpVtbl->get_DisplayColor(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_NetworkState(This,value) \
    ( (This)->lpVtbl->get_NetworkState(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_Voicemail(This,value) \
    ( (This)->lpVtbl->get_Voicemail(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_NetworkName(This,value) \
    ( (This)->lpVtbl->get_NetworkName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_CellularDetails(This,value) \
    ( (This)->lpVtbl->get_CellularDetails(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_Transport(This,value) \
    ( (This)->lpVtbl->get_Transport(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_CanDial(This,value) \
    ( (This)->lpVtbl->get_CanDial(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_SupportsTile(This,value) \
    ( (This)->lpVtbl->get_SupportsTile(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_VideoCallingCapabilities(This,value) \
    ( (This)->lpVtbl->get_VideoCallingCapabilities(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_get_LineConfiguration(This,value) \
    ( (This)->lpVtbl->get_LineConfiguration(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_IsImmediateDialNumberAsync(This,number,result) \
    ( (This)->lpVtbl->IsImmediateDialNumberAsync(This,number,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_Dial(This,number,displayName) \
    ( (This)->lpVtbl->Dial(This,number,displayName) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_DialWithOptions(This,options) \
    ( (This)->lpVtbl->DialWithOptions(This,options) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLine2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLine
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLine2[] = L"Windows.ApplicationModel.Calls.IPhoneLine2";
/* [object, uuid("0167F56A-5344-5D64-8AF3-A31A950E916A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *EnableTextReply )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TransportDeviceId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2 * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_EnableTextReply(This,value) \
    ( (This)->lpVtbl->EnableTextReply(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_get_TransportDeviceId(This,value) \
    ( (This)->lpVtbl->get_TransportDeviceId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLine2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineCellularDetails
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineCellularDetails
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails[] = L"Windows.ApplicationModel.Calls.IPhoneLineCellularDetails";
/* [object, uuid("192601D5-147C-4769-B673-98A5EC8426CB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetailsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SimState )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneSimState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SimSlotIndex )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsModemOn )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RegistrationRejectCode )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetNetworkOperatorDisplayText )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineNetworkOperatorDisplayTextLocation location,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetailsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetailsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_get_SimState(This,value) \
    ( (This)->lpVtbl->get_SimState(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_get_SimSlotIndex(This,value) \
    ( (This)->lpVtbl->get_SimSlotIndex(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_get_IsModemOn(This,value) \
    ( (This)->lpVtbl->get_IsModemOn(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_get_RegistrationRejectCode(This,value) \
    ( (This)->lpVtbl->get_RegistrationRejectCode(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_GetNetworkOperatorDisplayText(This,location,value) \
    ( (This)->lpVtbl->GetNetworkOperatorDisplayText(This,location,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineCellularDetails_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineConfiguration
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineConfiguration
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineConfiguration[] = L"Windows.ApplicationModel.Calls.IPhoneLineConfiguration";
/* [object, uuid("FE265862-F64F-4312-B2A8-4E257721AA95"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfigurationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVideoCallingEnabled )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedProperties )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration * This,
        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_IInspectable * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfigurationVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfigurationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_get_IsVideoCallingEnabled(This,value) \
    ( (This)->lpVtbl->get_IsVideoCallingEnabled(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_get_ExtendedProperties(This,value) \
    ( (This)->lpVtbl->get_ExtendedProperties(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLine
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineStatics[] = L"Windows.ApplicationModel.Calls.IPhoneLineStatics";
/* [object, uuid("F38B5F23-CEB0-404F-BCF2-BA9F697D8ADF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *FromIdAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics * This,
        /* [in] */GUID lineId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CPhoneLine * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_FromIdAsync(This,lineId,result) \
    ( (This)->lpVtbl->FromIdAsync(This,lineId,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineTransportDevice
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineTransportDevice
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice[] = L"Windows.ApplicationModel.Calls.IPhoneLineTransportDevice";
/* [object, uuid("EFA8F889-CFFA-59F4-97E4-74705B7DC490"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeviceId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Transport )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineTransport * value
        );
    HRESULT ( STDMETHODCALLTYPE *RequestAccessAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceAccessStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RegisterApp )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This
        );
    HRESULT ( STDMETHODCALLTYPE *RegisterAppForUser )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSystem_CIUser * user
        );
    HRESULT ( STDMETHODCALLTYPE *UnregisterApp )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This
        );
    HRESULT ( STDMETHODCALLTYPE *UnregisterAppForUser )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSystem_CIUser * user
        );
    HRESULT ( STDMETHODCALLTYPE *IsRegistered )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *Connect )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *ConnectAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_get_DeviceId(This,value) \
    ( (This)->lpVtbl->get_DeviceId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_get_Transport(This,value) \
    ( (This)->lpVtbl->get_Transport(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_RequestAccessAsync(This,operation) \
    ( (This)->lpVtbl->RequestAccessAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_RegisterApp(This) \
    ( (This)->lpVtbl->RegisterApp(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_RegisterAppForUser(This,user) \
    ( (This)->lpVtbl->RegisterAppForUser(This,user) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_UnregisterApp(This) \
    ( (This)->lpVtbl->UnregisterApp(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_UnregisterAppForUser(This,user) \
    ( (This)->lpVtbl->UnregisterAppForUser(This,user) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_IsRegistered(This,result) \
    ( (This)->lpVtbl->IsRegistered(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_Connect(This,result) \
    ( (This)->lpVtbl->Connect(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_ConnectAsync(This,operation) \
    ( (This)->lpVtbl->ConnectAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineTransportDeviceStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineTransportDevice
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineTransportDeviceStatics[] = L"Windows.ApplicationModel.Calls.IPhoneLineTransportDeviceStatics";
/* [object, uuid("0F3121AC-D609-51A1-96F3-FB00D1819252"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *FromId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
        /* [in] */__RPC__in HSTRING id,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDevice * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *GetDeviceSelector )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *GetDeviceSelectorForPhoneLineTransport )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineTransport transport,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_FromId(This,id,result) \
    ( (This)->lpVtbl->FromId(This,id,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_GetDeviceSelector(This,result) \
    ( (This)->lpVtbl->GetDeviceSelector(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_GetDeviceSelectorForPhoneLineTransport(This,transport,result) \
    ( (This)->lpVtbl->GetDeviceSelectorForPhoneLineTransport(This,transport,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineTransportDeviceStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineWatcher
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineWatcher
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineWatcher[] = L"Windows.ApplicationModel.Calls.IPhoneLineWatcher";
/* [object, uuid("8A45CD0A-6323-44E0-A6F6-9F21F64DC90A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Start )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This
        );
    HRESULT ( STDMETHODCALLTYPE *Stop )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LineAdded )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LineAdded )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LineRemoved )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LineRemoved )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LineUpdated )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_Windows__CApplicationModel__CCalls__CPhoneLineWatcherEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LineUpdated )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_EnumerationCompleted )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_EnumerationCompleted )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Stopped )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CPhoneLineWatcher_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Stopped )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneLineWatcherStatus * status
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_Start(This) \
    ( (This)->lpVtbl->Start(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_Stop(This) \
    ( (This)->lpVtbl->Stop(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_add_LineAdded(This,handler,token) \
    ( (This)->lpVtbl->add_LineAdded(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_remove_LineAdded(This,token) \
    ( (This)->lpVtbl->remove_LineAdded(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_add_LineRemoved(This,handler,token) \
    ( (This)->lpVtbl->add_LineRemoved(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_remove_LineRemoved(This,token) \
    ( (This)->lpVtbl->remove_LineRemoved(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_add_LineUpdated(This,handler,token) \
    ( (This)->lpVtbl->add_LineUpdated(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_remove_LineUpdated(This,token) \
    ( (This)->lpVtbl->remove_LineUpdated(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_add_EnumerationCompleted(This,handler,token) \
    ( (This)->lpVtbl->add_EnumerationCompleted(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_remove_EnumerationCompleted(This,token) \
    ( (This)->lpVtbl->remove_EnumerationCompleted(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_add_Stopped(This,handler,token) \
    ( (This)->lpVtbl->add_Stopped(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_remove_Stopped(This,token) \
    ( (This)->lpVtbl->remove_Stopped(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_get_Status(This,status) \
    ( (This)->lpVtbl->get_Status(This,status) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcher_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneLineWatcherEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneLineWatcherEventArgs[] = L"Windows.ApplicationModel.Calls.IPhoneLineWatcherEventArgs";
/* [object, uuid("D07C753E-9E12-4A37-82B7-AD535DAD6A67"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LineId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs * This,
        /* [retval, out] */__RPC__out GUID * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_get_LineId(This,value) \
    ( (This)->lpVtbl->get_LineId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneLineWatcherEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IPhoneVoicemail
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.PhoneVoicemail
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IPhoneVoicemail[] = L"Windows.ApplicationModel.Calls.IPhoneVoicemail";
/* [object, uuid("C9CE77F6-6E9F-3A8B-B727-6E0CF6998224"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemailVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Number )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MessageCount )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Type )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CPhoneVoicemailType * value
        );
    HRESULT ( STDMETHODCALLTYPE *DialVoicemailAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemailVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemailVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_get_Number(This,value) \
    ( (This)->lpVtbl->get_Number(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_get_MessageCount(This,value) \
    ( (This)->lpVtbl->get_MessageCount(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_get_Type(This,value) \
    ( (This)->lpVtbl->get_Type(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_DialVoicemailAsync(This,result) \
    ( (This)->lpVtbl->DialVoicemailAsync(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIPhoneVoicemail_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator";
/* [object, uuid("4F118BCF-E8EF-4434-9C5F-A8D893FAFE79"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ReserveCallResourcesAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */__RPC__in HSTRING taskEntryPoint,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * * operation
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_MuteStateChanged )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipCallCoordinator_Windows__CApplicationModel__CCalls__CMuteChangeEventArgs * muteChangeHandler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_MuteStateChanged )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *RequestNewIncomingCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING contactNumber,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * contactImage,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * brandingImage,
        /* [in] */__RPC__in HSTRING callDetails,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * ringtone,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia media,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan ringTimeout,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    HRESULT ( STDMETHODCALLTYPE *RequestNewOutgoingCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia media,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    HRESULT ( STDMETHODCALLTYPE *NotifyMuted )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This
        );
    HRESULT ( STDMETHODCALLTYPE *NotifyUnmuted )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This
        );
    HRESULT ( STDMETHODCALLTYPE *RequestOutgoingUpgradeToVideoCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */GUID callUpgradeGuid,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    HRESULT ( STDMETHODCALLTYPE *RequestIncomingUpgradeToVideoCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING contactNumber,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * contactImage,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * brandingImage,
        /* [in] */__RPC__in HSTRING callDetails,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * ringtone,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan ringTimeout,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    HRESULT ( STDMETHODCALLTYPE *TerminateCellularCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */GUID callUpgradeGuid
        );
    HRESULT ( STDMETHODCALLTYPE *CancelUpgrade )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * This,
        /* [in] */GUID callUpgradeGuid
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_ReserveCallResourcesAsync(This,taskEntryPoint,operation) \
    ( (This)->lpVtbl->ReserveCallResourcesAsync(This,taskEntryPoint,operation) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_add_MuteStateChanged(This,muteChangeHandler,token) \
    ( (This)->lpVtbl->add_MuteStateChanged(This,muteChangeHandler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_remove_MuteStateChanged(This,token) \
    ( (This)->lpVtbl->remove_MuteStateChanged(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_RequestNewIncomingCall(This,context,contactName,contactNumber,contactImage,serviceName,brandingImage,callDetails,ringtone,media,ringTimeout,call) \
    ( (This)->lpVtbl->RequestNewIncomingCall(This,context,contactName,contactNumber,contactImage,serviceName,brandingImage,callDetails,ringtone,media,ringTimeout,call) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_RequestNewOutgoingCall(This,context,contactName,serviceName,media,call) \
    ( (This)->lpVtbl->RequestNewOutgoingCall(This,context,contactName,serviceName,media,call) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_NotifyMuted(This) \
    ( (This)->lpVtbl->NotifyMuted(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_NotifyUnmuted(This) \
    ( (This)->lpVtbl->NotifyUnmuted(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_RequestOutgoingUpgradeToVideoCall(This,callUpgradeGuid,context,contactName,serviceName,call) \
    ( (This)->lpVtbl->RequestOutgoingUpgradeToVideoCall(This,callUpgradeGuid,context,contactName,serviceName,call) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_RequestIncomingUpgradeToVideoCall(This,context,contactName,contactNumber,contactImage,serviceName,brandingImage,callDetails,ringtone,ringTimeout,call) \
    ( (This)->lpVtbl->RequestIncomingUpgradeToVideoCall(This,context,contactName,contactNumber,contactImage,serviceName,brandingImage,callDetails,ringtone,ringTimeout,call) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_TerminateCellularCall(This,callUpgradeGuid) \
    ( (This)->lpVtbl->TerminateCellularCall(This,callUpgradeGuid) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_CancelUpgrade(This,callUpgradeGuid) \
    ( (This)->lpVtbl->CancelUpgrade(This,callUpgradeGuid) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator2[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator2";
/* [object, uuid("BEB4A9F3-C704-4234-89CE-E88CC0D28FBE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *SetupNewAcceptedCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2 * This,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING contactNumber,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia media,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_SetupNewAcceptedCall(This,context,contactName,contactNumber,serviceName,media,call) \
    ( (This)->lpVtbl->SetupNewAcceptedCall(This,context,contactName,contactNumber,serviceName,media,call) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator3
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator3[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator3";
/* [object, uuid("338D0CBF-9B55-4021-87CA-E64B9BD666C7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *RequestNewAppInitiatedCall )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING contactNumber,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia media,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestNewIncomingCallWithContactRemoteId )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3 * This,
        /* [in] */__RPC__in HSTRING context,
        /* [in] */__RPC__in HSTRING contactName,
        /* [in] */__RPC__in HSTRING contactNumber,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * contactImage,
        /* [in] */__RPC__in HSTRING serviceName,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * brandingImage,
        /* [in] */__RPC__in HSTRING callDetails,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * ringtone,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia media,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan ringTimeout,
        /* [in] */__RPC__in HSTRING contactRemoteId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * * call
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_RequestNewAppInitiatedCall(This,context,contactName,contactNumber,serviceName,media,call) \
    ( (This)->lpVtbl->RequestNewAppInitiatedCall(This,context,contactName,contactNumber,serviceName,media,call) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_RequestNewIncomingCallWithContactRemoteId(This,context,contactName,contactNumber,contactImage,serviceName,brandingImage,callDetails,ringtone,media,ringTimeout,contactRemoteId,call) \
    ( (This)->lpVtbl->RequestNewIncomingCallWithContactRemoteId(This,context,contactName,contactNumber,contactImage,serviceName,brandingImage,callDetails,ringtone,media,ringTimeout,contactRemoteId,call) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator3_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinator4
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinator4[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinator4";
/* [object, uuid("83737239-9311-468F-BB49-47E0DFB5D93E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *ReserveOneProcessCallResourcesAsync )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4 * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CCalls__CVoipPhoneCallResourceReservationStatus * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_ReserveOneProcessCallResourcesAsync(This,operation) \
    ( (This)->lpVtbl->ReserveOneProcessCallResourcesAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator4_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipCallCoordinatorStatics
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipCallCoordinatorStatics[] = L"Windows.ApplicationModel.Calls.IVoipCallCoordinatorStatics";
/* [object, uuid("7F5D1F2B-E04A-4D10-B31A-A55C922CC2FB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDefault )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinator * * coordinator
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_GetDefault(This,coordinator) \
    ( (This)->lpVtbl->GetDefault(This,coordinator) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipCallCoordinatorStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipPhoneCall
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipPhoneCall[] = L"Windows.ApplicationModel.Calls.IVoipPhoneCall";
/* [object, uuid("6CF1F19A-7794-4A5A-8C68-AE87947A6990"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCallVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_EndRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_EndRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_HoldRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_HoldRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ResumeRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallStateChangeEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ResumeRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_AnswerRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallAnswerEventArgs * acceptHandler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_AnswerRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_RejectRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CCalls__CVoipPhoneCall_Windows__CApplicationModel__CCalls__CCallRejectEventArgs * rejectHandler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_RejectRequested )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *NotifyCallHeld )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This
        );
    HRESULT ( STDMETHODCALLTYPE *NotifyCallActive )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This
        );
    HRESULT ( STDMETHODCALLTYPE *NotifyCallEnded )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContactName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ContactName )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartTime )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StartTime )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CDateTime value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CallMedia )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_CallMedia )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia value
        );
    HRESULT ( STDMETHODCALLTYPE *NotifyCallReady )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCallVtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCallVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_add_EndRequested(This,handler,token) \
    ( (This)->lpVtbl->add_EndRequested(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_remove_EndRequested(This,token) \
    ( (This)->lpVtbl->remove_EndRequested(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_add_HoldRequested(This,handler,token) \
    ( (This)->lpVtbl->add_HoldRequested(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_remove_HoldRequested(This,token) \
    ( (This)->lpVtbl->remove_HoldRequested(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_add_ResumeRequested(This,handler,token) \
    ( (This)->lpVtbl->add_ResumeRequested(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_remove_ResumeRequested(This,token) \
    ( (This)->lpVtbl->remove_ResumeRequested(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_add_AnswerRequested(This,acceptHandler,token) \
    ( (This)->lpVtbl->add_AnswerRequested(This,acceptHandler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_remove_AnswerRequested(This,token) \
    ( (This)->lpVtbl->remove_AnswerRequested(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_add_RejectRequested(This,rejectHandler,token) \
    ( (This)->lpVtbl->add_RejectRequested(This,rejectHandler,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_remove_RejectRequested(This,token) \
    ( (This)->lpVtbl->remove_RejectRequested(This,token) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_NotifyCallHeld(This) \
    ( (This)->lpVtbl->NotifyCallHeld(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_NotifyCallActive(This) \
    ( (This)->lpVtbl->NotifyCallActive(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_NotifyCallEnded(This) \
    ( (This)->lpVtbl->NotifyCallEnded(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_get_ContactName(This,value) \
    ( (This)->lpVtbl->get_ContactName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_put_ContactName(This,value) \
    ( (This)->lpVtbl->put_ContactName(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_get_StartTime(This,value) \
    ( (This)->lpVtbl->get_StartTime(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_put_StartTime(This,value) \
    ( (This)->lpVtbl->put_StartTime(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_get_CallMedia(This,value) \
    ( (This)->lpVtbl->get_CallMedia(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_put_CallMedia(This,value) \
    ( (This)->lpVtbl->put_CallMedia(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_NotifyCallReady(This) \
    ( (This)->lpVtbl->NotifyCallReady(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipPhoneCall2
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipPhoneCall
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipPhoneCall2[] = L"Windows.ApplicationModel.Calls.IVoipPhoneCall2";
/* [object, uuid("741B46E1-245F-41F3-9399-3141D25B52E3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *TryShowAppUI )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2 * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_TryShowAppUI(This) \
    ( (This)->lpVtbl->TryShowAppUI(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall2_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.ApplicationModel.Calls.IVoipPhoneCall3
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.ApplicationModel.Calls.IVoipPhoneCall2
 *     Windows.ApplicationModel.Calls.IVoipPhoneCall
 *
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Calls_IVoipPhoneCall3[] = L"Windows.ApplicationModel.Calls.IVoipPhoneCall3";
/* [object, uuid("0D891522-E258-4AA9-907A-1AA413C25523"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *NotifyCallAccepted )(
        __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3 * This,
        /* [in] */__x_ABI_CWindows_CApplicationModel_CCalls_CVoipPhoneCallMedia media
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_NotifyCallAccepted(This,media) \
    ( (This)->lpVtbl->NotifyCallAccepted(This,media) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CCalls_CIVoipPhoneCall3_INTERFACE_DEFINED__) */
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.ApplicationModel.Calls.CallAnswerEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ICallAnswerEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_CallAnswerEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_CallAnswerEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_CallAnswerEventArgs[] = L"Windows.ApplicationModel.Calls.CallAnswerEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.CallRejectEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ICallRejectEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_CallRejectEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_CallRejectEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_CallRejectEventArgs[] = L"Windows.ApplicationModel.Calls.CallRejectEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.CallStateChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ICallStateChangeEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_CallStateChangeEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_CallStateChangeEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_CallStateChangeEventArgs[] = L"Windows.ApplicationModel.Calls.CallStateChangeEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.LockScreenCallEndCallDeferral
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ILockScreenCallEndCallDeferral ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndCallDeferral_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndCallDeferral_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_LockScreenCallEndCallDeferral[] = L"Windows.ApplicationModel.Calls.LockScreenCallEndCallDeferral";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ILockScreenCallEndRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallEndRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_LockScreenCallEndRequestedEventArgs[] = L"Windows.ApplicationModel.Calls.LockScreenCallEndRequestedEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.LockScreenCallUI
 *
 * Introduced to Windows.ApplicationModel.Calls.LockScreenCallContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.ILockScreenCallUI ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallUI_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_LockScreenCallUI_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_LockScreenCallUI[] = L"Windows.ApplicationModel.Calls.LockScreenCallUI";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_LOCKSCREENCALLCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.MuteChangeEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IMuteChangeEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_MuteChangeEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_MuteChangeEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_MuteChangeEventArgs[] = L"Windows.ApplicationModel.Calls.MuteChangeEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallBlocking
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallBlockingStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallBlocking_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallBlocking_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallBlocking[] = L"Windows.ApplicationModel.Calls.PhoneCallBlocking";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntry
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntry ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntry_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntry_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntry[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntry";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Type can be activated via the Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddressFactory interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryAddress ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryAddress_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryAddress_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryAddress[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntryAddress";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryQueryOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryQueryOptions_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryQueryOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryQueryOptions[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntryQueryOptions";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryEntryReader
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryEntryReader ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryReader_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryReader_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryEntryReader[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryEntryReader";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics2 interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryManager[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryManagerForUser
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryManagerForUser ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManagerForUser_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryManagerForUser_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryManagerForUser[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryManagerForUser";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallHistoryStore
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallHistoryStore ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryStore_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallHistoryStore_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallHistoryStore[] = L"Windows.ApplicationModel.Calls.PhoneCallHistoryStore";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallManager
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallManagerStatics2 interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallManagerStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallManager[] = L"Windows.ApplicationModel.Calls.PhoneCallManager";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallStore
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallStore ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallStore_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallStore_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallStore[] = L"Windows.ApplicationModel.Calls.PhoneCallStore";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilities ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilities_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilities_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilities[] = L"Windows.ApplicationModel.Calls.PhoneCallVideoCapabilities";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneCallVideoCapabilitiesManager
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneCallVideoCapabilitiesManagerStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilitiesManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilitiesManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneCallVideoCapabilitiesManager[] = L"Windows.ApplicationModel.Calls.PhoneCallVideoCapabilitiesManager";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneDialOptions
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneDialOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneDialOptions_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneDialOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneDialOptions[] = L"Windows.ApplicationModel.Calls.PhoneDialOptions";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLine
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneLineStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLine ** Default Interface **
 *    Windows.ApplicationModel.Calls.IPhoneLine2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLine_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLine_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLine[] = L"Windows.ApplicationModel.Calls.PhoneLine";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineCellularDetails
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineCellularDetails ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineCellularDetails_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineCellularDetails_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineCellularDetails[] = L"Windows.ApplicationModel.Calls.PhoneLineCellularDetails";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineConfiguration
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineConfiguration_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineConfiguration[] = L"Windows.ApplicationModel.Calls.PhoneLineConfiguration";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineTransportDevice
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IPhoneLineTransportDeviceStatics interface starting with version 5.0 of the Windows.ApplicationModel.Calls.CallsPhoneContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineTransportDevice ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineTransportDevice_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineTransportDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineTransportDevice[] = L"Windows.ApplicationModel.Calls.PhoneLineTransportDevice";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineWatcher
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineWatcher ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcher_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcher_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineWatcher[] = L"Windows.ApplicationModel.Calls.PhoneLineWatcher";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneLineWatcherEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcherEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneLineWatcherEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneLineWatcherEventArgs[] = L"Windows.ApplicationModel.Calls.PhoneLineWatcherEventArgs";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.PhoneVoicemail
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsPhoneContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IPhoneVoicemail ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneVoicemail_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_PhoneVoicemail_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_PhoneVoicemail[] = L"Windows.ApplicationModel.Calls.PhoneVoicemail";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.VoipCallCoordinator
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Calls.IVoipCallCoordinatorStatics interface starting with version 1.0 of the Windows.ApplicationModel.Calls.CallsVoipContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator ** Default Interface **
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator2
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator3
 *    Windows.ApplicationModel.Calls.IVoipCallCoordinator4
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipCallCoordinator_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipCallCoordinator_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_VoipCallCoordinator[] = L"Windows.ApplicationModel.Calls.VoipCallCoordinator";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.ApplicationModel.Calls.VoipPhoneCall
 *
 * Introduced to Windows.ApplicationModel.Calls.CallsVoipContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Calls.IVoipPhoneCall ** Default Interface **
 *    Windows.ApplicationModel.Calls.IVoipPhoneCall2
 *    Windows.ApplicationModel.Calls.IVoipPhoneCall3
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipPhoneCall_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Calls_VoipPhoneCall_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Calls_VoipPhoneCall[] = L"Windows.ApplicationModel.Calls.VoipPhoneCall";
#endif
#endif // WINDOWS_APPLICATIONMODEL_CALLS_CALLSVOIPCONTRACT_VERSION >= 0x10000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eapplicationmodel2Ecalls_p_h__

#endif // __windows2Eapplicationmodel2Ecalls_h__
