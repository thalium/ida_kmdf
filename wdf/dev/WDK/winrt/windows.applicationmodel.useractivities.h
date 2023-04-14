/* Header file automatically generated from windows.applicationmodel.useractivities.idl */
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
#ifndef __windows2Eapplicationmodel2Euseractivities_h__
#define __windows2Eapplicationmodel2Euseractivities_h__
#ifndef __windows2Eapplicationmodel2Euseractivities_p_h__
#define __windows2Eapplicationmodel2Euseractivities_p_h__


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

#if !defined(WINDOWS_UI_SHELL_SECURITYAPPMANAGERCONTRACT_VERSION)
#define WINDOWS_UI_SHELL_SECURITYAPPMANAGERCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_UI_SHELL_SECURITYAPPMANAGERCONTRACT_VERSION)

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
#include "Windows.Security.Credentials.h"
#include "Windows.System.h"
#include "Windows.UI.h"
#include "Windows.UI.Shell.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivity;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity ABI::Windows::ApplicationModel::UserActivities::IUserActivity

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivity2;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 ABI::Windows::ApplicationModel::UserActivities::IUserActivity2

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivity3;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 ABI::Windows::ApplicationModel::UserActivities::IUserActivity3

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityAttribution;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution ABI::Windows::ApplicationModel::UserActivities::IUserActivityAttribution

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityAttributionFactory;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory ABI::Windows::ApplicationModel::UserActivities::IUserActivityAttributionFactory

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityChannel;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannel

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityChannel2;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannel2

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityChannelStatics;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityChannelStatics2;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics2

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityChannelStatics3;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannelStatics3

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityContentInfo;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo ABI::Windows::ApplicationModel::UserActivities::IUserActivityContentInfo

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityContentInfoStatics;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics ABI::Windows::ApplicationModel::UserActivities::IUserActivityContentInfoStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityFactory;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory ABI::Windows::ApplicationModel::UserActivities::IUserActivityFactory

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityRequest;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequest

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityRequestManager;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityRequestManagerStatics;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestManagerStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityRequestedEventArgs;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivitySession;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession ABI::Windows::ApplicationModel::UserActivities::IUserActivitySession

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivitySessionHistoryItem;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityStatics;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics ABI::Windows::ApplicationModel::UserActivities::IUserActivityStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityVisualElements;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements ABI::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                interface IUserActivityVisualElements2;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 ABI::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements2

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivity;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#define DEF___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("2ca0633b-0505-5f88-a98f-8e7c5b08f25b"))
IIterator<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivity*, ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.ApplicationModel.UserActivities.UserActivity>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t;
#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
//#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#define DEF___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("37e6ab55-1f30-5622-9778-1bdc07ac799f"))
IIterable<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivity*, ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.ApplicationModel.UserActivities.UserActivity>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t;
#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
//#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivitySessionHistoryItem;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#define DEF___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("88c0e720-7442-553a-86d7-43dfe7d21929"))
IIterator<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*, ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t;
#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
//#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#define DEF___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("29439e38-9cf0-51c7-a549-4469039caf79"))
IIterable<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*, ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t;
#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
//#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#define DEF___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("192a5116-61d6-5e18-8679-0af4f7090816"))
IVectorView<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivity*, ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.ApplicationModel.UserActivities.UserActivity>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t;
#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
//#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#define DEF___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("006a83c1-59ff-5870-8d8d-0583814af160"))
IVectorView<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*, ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t;
#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
//#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#define DEF___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e3004e95-0b05-55dc-bf3b-be06fae03152"))
IVector<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivity*, ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<Windows.ApplicationModel.UserActivities.UserActivity>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t;
#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
//#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#define DEF___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8765461c-2f90-586e-83ec-58b3e4309480"))
IVector<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*, ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<ABI::Windows::ApplicationModel::UserActivities::UserActivitySessionHistoryItem*> __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t;
#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
//#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("652507c7-0bc6-5d0b-82be-97ad2257b685"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivity*, ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.UserActivities.UserActivity>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("35095983-7790-5974-a660-1c2dbdd2efa7"))
IAsyncOperation<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivity*, ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.UserActivities.UserActivity>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::UserActivities::UserActivity*> __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::UserActivities::IUserActivity*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#define DEF___FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3df67ad8-7d8d-52bd-9892-0ff9bf93fc80"))
IAsyncOperationCompletedHandler<__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem*> : IAsyncOperationCompletedHandler_impl<__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Foundation.Collections.IVector`1<Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem*> __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t;
#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>*>
//#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#define DEF___FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d0d0c30a-255c-5238-a7a2-aa905d383919"))
IAsyncOperation<__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem*> : IAsyncOperation_impl<__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Foundation.Collections.IVector`1<Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<__FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem*> __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t;
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::__FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>*>
//#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVector<ABI::Windows::ApplicationModel::UserActivities::IUserActivitySessionHistoryItem*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityRequestManager;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityRequestedEventArgs;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b71f6fda-21f5-5bcd-b83b-6c9eadff2410"))
ITypedEventHandler<ABI::Windows::ApplicationModel::UserActivities::UserActivityRequestManager*,ABI::Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivityRequestManager*, ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs*, ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.ApplicationModel.UserActivities.UserActivityRequestManager, Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::ApplicationModel::UserActivities::UserActivityRequestManager*,ABI::Windows::ApplicationModel::UserActivities::UserActivityRequestedEventArgs*> __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager*,ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager*,ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Foundation {
            struct DateTime;
            
        } /* Foundation */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CFoundation__CDateTime_USE
#define DEF___FIReference_1_Windows__CFoundation__CDateTime_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("5541d8a7-497c-5aa4-86fc-7713adbf2a2c"))
IReference<struct ABI::Windows::Foundation::DateTime> : IReference_impl<struct ABI::Windows::Foundation::DateTime> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Foundation.DateTime>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::Foundation::DateTime> __FIReference_1_Windows__CFoundation__CDateTime_t;
#define __FIReference_1_Windows__CFoundation__CDateTime ABI::Windows::Foundation::__FIReference_1_Windows__CFoundation__CDateTime_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CFoundation__CDateTime ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::DateTime>
//#define __FIReference_1_Windows__CFoundation__CDateTime_t ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::DateTime>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CFoundation__CDateTime_USE */





namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct DateTime DateTime;
            
        } /* Foundation */
    } /* Windows */} /* ABI */

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
        namespace Security {
            namespace Credentials {
                class WebAccount;
            } /* Credentials */
        } /* Security */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Security {
            namespace Credentials {
                interface IWebAccount;
            } /* Credentials */
        } /* Security */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount ABI::Windows::Security::Credentials::IWebAccount

#endif // ____x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount_FWD_DEFINED__





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



#ifndef ____x_ABI_CWindows_CUI_CShell_CIAdaptiveCard_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CShell_CIAdaptiveCard_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Shell {
                interface IAdaptiveCard;
            } /* Shell */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CShell_CIAdaptiveCard ABI::Windows::UI::Shell::IAdaptiveCard

#endif // ____x_ABI_CWindows_CUI_CShell_CIAdaptiveCard_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                
                typedef enum UserActivityState : int UserActivityState;
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
























namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityAttribution;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityChannel;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityContentInfo;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityRequest;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivitySession;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                class UserActivityVisualElements;
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */










/*
 *
 * Struct Windows.ApplicationModel.UserActivities.UserActivityState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [v1_enum, contract] */
                enum UserActivityState : int
                {
                    UserActivityState_New = 0,
                    UserActivityState_Published = 1,
                };
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivity
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivity[] = L"Windows.ApplicationModel.UserActivities.IUserActivity";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("FC103E9E-2CAB-4D36-AEA2-B4BB556CEF0F"), exclusiveto, contract] */
                MIDL_INTERFACE("FC103E9E-2CAB-4D36-AEA2-B4BB556CEF0F")
                IUserActivity : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_State(
                        /* [retval, out] */__RPC__out ABI::Windows::ApplicationModel::UserActivities::UserActivityState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ActivityId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_VisualElements(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityVisualElements * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContentUri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ContentUri(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContentType(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ContentType(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_FallbackUri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_FallbackUri(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ActivationUri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ActivationUri(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContentInfo(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityContentInfo * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ContentInfo(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityContentInfo * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SaveAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateSession(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivitySession * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivity=_uuidof(IUserActivity);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivity2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivity2[] = L"Windows.ApplicationModel.UserActivities.IUserActivity2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("9DC40C62-08C4-47AC-AA9C-2BB2221C55FD"), exclusiveto, contract] */
                MIDL_INTERFACE("9DC40C62-08C4-47AC-AA9C-2BB2221C55FD")
                IUserActivity2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE ToJson(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivity2=_uuidof(IUserActivity2);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivity3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivity3[] = L"Windows.ApplicationModel.UserActivities.IUserActivity3";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("E7697744-E1A2-5147-8E06-55F1EEEF271C"), exclusiveto, contract] */
                MIDL_INTERFACE("E7697744-E1A2-5147-8E06-55F1EEEF271C")
                IUserActivity3 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRoamable(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsRoamable(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivity3=_uuidof(IUserActivity3);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityAttribution
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityAttribution
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityAttribution[] = L"Windows.ApplicationModel.UserActivities.IUserActivityAttribution";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("34A5C8B5-86DD-4AEC-A491-6A4FAEA5D22E"), exclusiveto, contract] */
                MIDL_INTERFACE("34A5C8B5-86DD-4AEC-A491-6A4FAEA5D22E")
                IUserActivityAttribution : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IconUri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IconUri(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AlternateText(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AlternateText(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AddImageQuery(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AddImageQuery(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityAttribution=_uuidof(IUserActivityAttribution);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityAttribution
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityAttributionFactory[] = L"Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("E62BD252-C566-4F42-9974-916C4D76377E"), exclusiveto, contract] */
                MIDL_INTERFACE("E62BD252-C566-4F42-9974-916C4D76377E")
                IUserActivityAttributionFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateWithUri(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * iconUri,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityAttribution * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityAttributionFactory=_uuidof(IUserActivityAttributionFactory);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannel[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannel";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("BAC0F8B8-A0E4-483B-B948-9CBABD06070C"), exclusiveto, contract] */
                MIDL_INTERFACE("BAC0F8B8-A0E4-483B-B948-9CBABD06070C")
                IUserActivityChannel : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE GetOrCreateUserActivityAsync(
                        /* [in] */__RPC__in HSTRING activityId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DeleteActivityAsync(
                        /* [in] */__RPC__in HSTRING activityId,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DeleteAllActivitiesAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityChannel=_uuidof(IUserActivityChannel);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannel2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannel2[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannel2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("1698E35B-EB7E-4EA0-BF17-A459E8BE706C"), exclusiveto, contract] */
                MIDL_INTERFACE("1698E35B-EB7E-4EA0-BF17-A459E8BE706C")
                IUserActivityChannel2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetRecentUserActivitiesAsync(
                        /* [in] */INT32 maxUniqueActivities,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSessionHistoryItemsForUserActivityAsync(
                        /* [in] */__RPC__in HSTRING activityId,
                        /* [in] */ABI::Windows::Foundation::DateTime startTime,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityChannel2=_uuidof(IUserActivityChannel2);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("C8C005AB-198D-4D80-ABB2-C9775EC4A729"), exclusiveto, contract] */
                MIDL_INTERFACE("C8C005AB-198D-4D80-ABB2-C9775EC4A729")
                IUserActivityChannelStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDefault(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannel * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityChannelStatics=_uuidof(IUserActivityChannelStatics);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics2[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("8E87DE30-AA4F-4624-9AD0-D40F3BA0317C"), exclusiveto, contract] */
                MIDL_INTERFACE("8E87DE30-AA4F-4624-9AD0-D40F3BA0317C")
                IUserActivityChannelStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE DisableAutoSessionCreation(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryGetForWebAccount(
                        /* [in] */__RPC__in_opt ABI::Windows::Security::Credentials::IWebAccount * account,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannel * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityChannelStatics2=_uuidof(IUserActivityChannelStatics2);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics3[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("53BC4DDB-BBDF-5984-802A-5305874E205C"), exclusiveto, contract] */
                MIDL_INTERFACE("53BC4DDB-BBDF-5984-802A-5305874E205C")
                IUserActivityChannelStatics3 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetForUser(
                        /* [in] */__RPC__in_opt ABI::Windows::System::IUser * user,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityChannel * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityChannelStatics3=_uuidof(IUserActivityChannelStatics3);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityContentInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityContentInfo[] = L"Windows.ApplicationModel.UserActivities.IUserActivityContentInfo";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("B399E5AD-137F-409D-822D-E1AF27CE08DC"), contract] */
                MIDL_INTERFACE("B399E5AD-137F-409D-822D-E1AF27CE08DC")
                IUserActivityContentInfo : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE ToJson(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityContentInfo=_uuidof(IUserActivityContentInfo);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityContentInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityContentInfoStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("9988C34B-0386-4BC9-968A-8200B004144F"), exclusiveto, contract] */
                MIDL_INTERFACE("9988C34B-0386-4BC9-968A-8200B004144F")
                IUserActivityContentInfoStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE FromJson(
                        /* [in] */__RPC__in HSTRING value,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityContentInfo * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityContentInfoStatics=_uuidof(IUserActivityContentInfoStatics);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityFactory[] = L"Windows.ApplicationModel.UserActivities.IUserActivityFactory";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("7C385758-361D-4A67-8A3B-34CA2978F9A3"), exclusiveto, contract] */
                MIDL_INTERFACE("7C385758-361D-4A67-8A3B-34CA2978F9A3")
                IUserActivityFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateWithActivityId(
                        /* [in] */__RPC__in HSTRING activityId,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivity * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityFactory=_uuidof(IUserActivityFactory);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequest
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequest[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequest";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("A0EF6355-CF35-4FF0-8833-50CB4B72E06D"), exclusiveto, contract] */
                MIDL_INTERFACE("A0EF6355-CF35-4FF0-8833-50CB4B72E06D")
                IUserActivityRequest : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE SetUserActivity(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivity * activity
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityRequest=_uuidof(IUserActivityRequest);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequestManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequestManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequestManager";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("0C30BE4E-903D-48D6-82D4-4043ED57791B"), exclusiveto, contract] */
                MIDL_INTERFACE("0C30BE4E-903D-48D6-82D4-4043ED57791B")
                IUserActivityRequestManager : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_UserActivityRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_UserActivityRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityRequestManager=_uuidof(IUserActivityRequestManager);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequestManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequestManagerStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("C0392DF1-224A-432C-81E5-0C76B4C4CEFA"), exclusiveto, contract] */
                MIDL_INTERFACE("C0392DF1-224A-432C-81E5-0C76B4C4CEFA")
                IUserActivityRequestManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequestManager * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityRequestManagerStatics=_uuidof(IUserActivityRequestManagerStatics);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequestedEventArgs[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("A4CC7A4C-8229-4CFD-A3BC-C61D318575A4"), exclusiveto, contract] */
                MIDL_INTERFACE("A4CC7A4C-8229-4CFD-A3BC-C61D318575A4")
                IUserActivityRequestedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Request(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityRequest * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityRequestedEventArgs=_uuidof(IUserActivityRequestedEventArgs);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivitySession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivitySession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivitySession[] = L"Windows.ApplicationModel.UserActivities.IUserActivitySession";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("AE434D78-24FA-44A3-AD48-6EDA61AA1924"), exclusiveto, contract] */
                MIDL_INTERFACE("AE434D78-24FA-44A3-AD48-6EDA61AA1924")
                IUserActivitySession : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ActivityId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivitySession=_uuidof(IUserActivitySession);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem[] = L"Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("E8D59BD3-3E5D-49FD-98D7-6DA97521E255"), exclusiveto, contract] */
                MIDL_INTERFACE("E8D59BD3-3E5D-49FD-98D7-6DA97521E255")
                IUserActivitySessionHistoryItem : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UserActivity(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivity * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EndTime(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CDateTime * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivitySessionHistoryItem=_uuidof(IUserActivitySessionHistoryItem);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("8C8FD333-0E09-47F6-9AC7-95CF5C39367B"), exclusiveto, contract] */
                MIDL_INTERFACE("8C8FD333-0E09-47F6-9AC7-95CF5C39367B")
                IUserActivityStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE TryParseFromJson(
                        /* [in] */__RPC__in HSTRING json,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivity * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryParseFromJsonArray(
                        /* [in] */__RPC__in HSTRING json,
                        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ToJsonArray(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * activities,
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityStatics=_uuidof(IUserActivityStatics);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityVisualElements
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityVisualElements
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements[] = L"Windows.ApplicationModel.UserActivities.IUserActivityVisualElements";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("94757513-262F-49EF-BBBF-9B75D2E85250"), exclusiveto, contract] */
                MIDL_INTERFACE("94757513-262F-49EF-BBBF-9B75D2E85250")
                IUserActivityVisualElements : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayText(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DisplayText(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Description(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Description(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BackgroundColor(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BackgroundColor(
                        /* [in] */ABI::Windows::UI::Color value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Attribution(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityAttribution * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Attribution(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::UserActivities::IUserActivityAttribution * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Content(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::Shell::IAdaptiveCard * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Content(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Shell::IAdaptiveCard * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityVisualElements=_uuidof(IUserActivityVisualElements);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityVisualElements
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements2[] = L"Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace UserActivities {
                /* [object, uuid("CAAE7FC7-3EEF-4359-825C-9D51B9220DE3"), exclusiveto, contract] */
                MIDL_INTERFACE("CAAE7FC7-3EEF-4359-825C-9D51B9220DE3")
                IUserActivityVisualElements2 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AttributionDisplayText(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AttributionDisplayText(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IUserActivityVisualElements2=_uuidof(IUserActivityVisualElements2);
                
            } /* UserActivities */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivity
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.ApplicationModel.UserActivities.IUserActivityFactory interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivity ** Default Interface **
 *    Windows.ApplicationModel.UserActivities.IUserActivity2
 *    Windows.ApplicationModel.UserActivities.IUserActivity3
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivity_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivity_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivity[] = L"Windows.ApplicationModel.UserActivities.UserActivity";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityAttribution
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Type can be activated via the Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityAttribution ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityAttribution_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityAttribution_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityAttribution[] = L"Windows.ApplicationModel.UserActivities.UserActivityAttribution";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2 interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityChannel ** Default Interface **
 *    Windows.ApplicationModel.UserActivities.IUserActivityChannel2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityChannel_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityChannel_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityChannel[] = L"Windows.ApplicationModel.UserActivities.UserActivityChannel";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityContentInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityContentInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityContentInfo_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityContentInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityContentInfo[] = L"Windows.ApplicationModel.UserActivities.UserActivityContentInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityRequest ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequest_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequest_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityRequest[] = L"Windows.ApplicationModel.UserActivities.UserActivityRequest";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityRequestManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityRequestManager ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityRequestManager[] = L"Windows.ApplicationModel.UserActivities.UserActivityRequestManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityRequestedEventArgs[] = L"Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivitySession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivitySession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySession_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivitySession[] = L"Windows.ApplicationModel.UserActivities.UserActivitySession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySessionHistoryItem_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySessionHistoryItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivitySessionHistoryItem[] = L"Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityVisualElements
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityVisualElements ** Default Interface **
 *    Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityVisualElements_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityVisualElements_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityVisualElements[] = L"Windows.ApplicationModel.UserActivities.UserActivityVisualElements";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2;

#endif // ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

typedef struct __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl;

interface __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity
{
    CONST_VTBL struct __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

typedef  struct __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivity **first);

    END_INTERFACE
} __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl;

interface __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity
{
    CONST_VTBL struct __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

typedef struct __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl;

interface __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem
{
    CONST_VTBL struct __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

typedef  struct __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem **first);

    END_INTERFACE
} __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl;

interface __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem
{
    CONST_VTBL struct __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

typedef struct __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
            /* [in] */ __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl;

interface __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity
{
    CONST_VTBL struct __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

typedef struct __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
            /* [in] */ __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl;

interface __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem
{
    CONST_VTBL struct __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__)
#define ____FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

typedef interface __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

typedef struct __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivity **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *value);

    END_INTERFACE
} __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl;

interface __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity
{
    CONST_VTBL struct __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

typedef interface __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

typedef struct __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [in] */ __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * *value);

    END_INTERFACE
} __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl;

interface __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem
{
    CONST_VTBL struct __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CUserActivities__CUserActivity **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivityVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

typedef struct __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl;

interface __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem;

typedef struct __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * This, /* [retval][out] */ __RPC__out __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * *results);
    END_INTERFACE
} __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl;

interface __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem
{
    CONST_VTBL struct __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

struct __x_ABI_CWindows_CFoundation_CDateTime;

#if !defined(____FIReference_1_Windows__CFoundation__CDateTime_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CFoundation__CDateTime_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CFoundation__CDateTime __FIReference_1_Windows__CFoundation__CDateTime;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CFoundation__CDateTime;

typedef struct __FIReference_1_Windows__CFoundation__CDateTimeVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CFoundation__CDateTime * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CFoundation_CDateTime *value);
    END_INTERFACE
} __FIReference_1_Windows__CFoundation__CDateTimeVtbl;

interface __FIReference_1_Windows__CFoundation__CDateTime
{
    CONST_VTBL struct __FIReference_1_Windows__CFoundation__CDateTimeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CFoundation__CDateTime_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CFoundation__CDateTime_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CFoundation__CDateTime_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CFoundation__CDateTime_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CFoundation__CDateTime_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CFoundation__CDateTime_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CFoundation__CDateTime_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CFoundation__CDateTime_INTERFACE_DEFINED__




typedef struct __x_ABI_CWindows_CFoundation_CDateTime __x_ABI_CWindows_CFoundation_CDateTime;

#ifndef ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIDeferral __x_ABI_CWindows_CFoundation_CIDeferral;

#endif // ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIAsyncAction __x_ABI_CWindows_CFoundation_CIAsyncAction;

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__



#ifndef ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIUriRuntimeClass __x_ABI_CWindows_CFoundation_CIUriRuntimeClass;

#endif // ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount_FWD_DEFINED__
#define ____x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount;

#endif // ____x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CIUser __x_ABI_CWindows_CSystem_CIUser;

#endif // ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__





typedef struct __x_ABI_CWindows_CUI_CColor __x_ABI_CWindows_CUI_CColor;



#ifndef ____x_ABI_CWindows_CUI_CShell_CIAdaptiveCard_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CShell_CIAdaptiveCard_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CShell_CIAdaptiveCard __x_ABI_CWindows_CUI_CShell_CIAdaptiveCard;

#endif // ____x_ABI_CWindows_CUI_CShell_CIAdaptiveCard_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CApplicationModel_CUserActivities_CUserActivityState __x_ABI_CWindows_CApplicationModel_CUserActivities_CUserActivityState;









































/*
 *
 * Struct Windows.ApplicationModel.UserActivities.UserActivityState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CApplicationModel_CUserActivities_CUserActivityState
{
    UserActivityState_New = 0,
    UserActivityState_Published = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivity
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivity[] = L"Windows.ApplicationModel.UserActivities.IUserActivity";
/* [object, uuid("FC103E9E-2CAB-4D36-AEA2-B4BB556CEF0F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_State )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CApplicationModel_CUserActivities_CUserActivityState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ActivityId )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_VisualElements )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContentUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ContentUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContentType )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ContentType )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_FallbackUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_FallbackUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ActivationUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ActivationUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContentInfo )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ContentInfo )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * value
        );
    HRESULT ( STDMETHODCALLTYPE *SaveAsync )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CreateSession )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_State(This,value) \
    ( (This)->lpVtbl->get_State(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_ActivityId(This,value) \
    ( (This)->lpVtbl->get_ActivityId(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_VisualElements(This,value) \
    ( (This)->lpVtbl->get_VisualElements(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_ContentUri(This,value) \
    ( (This)->lpVtbl->get_ContentUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_put_ContentUri(This,value) \
    ( (This)->lpVtbl->put_ContentUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_ContentType(This,value) \
    ( (This)->lpVtbl->get_ContentType(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_put_ContentType(This,value) \
    ( (This)->lpVtbl->put_ContentType(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_FallbackUri(This,value) \
    ( (This)->lpVtbl->get_FallbackUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_put_FallbackUri(This,value) \
    ( (This)->lpVtbl->put_FallbackUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_ActivationUri(This,value) \
    ( (This)->lpVtbl->get_ActivationUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_put_ActivationUri(This,value) \
    ( (This)->lpVtbl->put_ActivationUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_get_ContentInfo(This,value) \
    ( (This)->lpVtbl->get_ContentInfo(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_put_ContentInfo(This,value) \
    ( (This)->lpVtbl->put_ContentInfo(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_SaveAsync(This,operation) \
    ( (This)->lpVtbl->SaveAsync(This,operation) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_CreateSession(This,result) \
    ( (This)->lpVtbl->CreateSession(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivity2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivity2[] = L"Windows.ApplicationModel.UserActivities.IUserActivity2";
/* [object, uuid("9DC40C62-08C4-47AC-AA9C-2BB2221C55FD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ToJson )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2 * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_ToJson(This,result) \
    ( (This)->lpVtbl->ToJson(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivity3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivity3[] = L"Windows.ApplicationModel.UserActivities.IUserActivity3";
/* [object, uuid("E7697744-E1A2-5147-8E06-55F1EEEF271C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRoamable )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsRoamable )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3 * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_get_IsRoamable(This,value) \
    ( (This)->lpVtbl->get_IsRoamable(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_put_IsRoamable(This,value) \
    ( (This)->lpVtbl->put_IsRoamable(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityAttribution
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityAttribution
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityAttribution[] = L"Windows.ApplicationModel.UserActivities.IUserActivityAttribution";
/* [object, uuid("34A5C8B5-86DD-4AEC-A491-6A4FAEA5D22E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IconUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IconUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AlternateText )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AlternateText )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AddImageQuery )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AddImageQuery )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_get_IconUri(This,value) \
    ( (This)->lpVtbl->get_IconUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_put_IconUri(This,value) \
    ( (This)->lpVtbl->put_IconUri(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_get_AlternateText(This,value) \
    ( (This)->lpVtbl->get_AlternateText(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_put_AlternateText(This,value) \
    ( (This)->lpVtbl->put_AlternateText(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_get_AddImageQuery(This,value) \
    ( (This)->lpVtbl->get_AddImageQuery(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_put_AddImageQuery(This,value) \
    ( (This)->lpVtbl->put_AddImageQuery(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityAttribution
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityAttributionFactory[] = L"Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory";
/* [object, uuid("E62BD252-C566-4F42-9974-916C4D76377E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateWithUri )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * iconUri,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactoryVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_CreateWithUri(This,iconUri,value) \
    ( (This)->lpVtbl->CreateWithUri(This,iconUri,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttributionFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannel[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannel";
/* [object, uuid("BAC0F8B8-A0E4-483B-B948-9CBABD06070C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *GetOrCreateUserActivityAsync )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
        /* [in] */__RPC__in HSTRING activityId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CUserActivities__CUserActivity * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *DeleteActivityAsync )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
        /* [in] */__RPC__in HSTRING activityId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *DeleteAllActivitiesAsync )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_GetOrCreateUserActivityAsync(This,activityId,operation) \
    ( (This)->lpVtbl->GetOrCreateUserActivityAsync(This,activityId,operation) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_DeleteActivityAsync(This,activityId,operation) \
    ( (This)->lpVtbl->DeleteActivityAsync(This,activityId,operation) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_DeleteAllActivitiesAsync(This,operation) \
    ( (This)->lpVtbl->DeleteAllActivitiesAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannel2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannel2[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannel2";
/* [object, uuid("1698E35B-EB7E-4EA0-BF17-A459E8BE706C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetRecentUserActivitiesAsync )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This,
        /* [in] */INT32 maxUniqueActivities,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetSessionHistoryItemsForUserActivityAsync )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2 * This,
        /* [in] */__RPC__in HSTRING activityId,
        /* [in] */__x_ABI_CWindows_CFoundation_CDateTime startTime,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivitySessionHistoryItem * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_GetRecentUserActivitiesAsync(This,maxUniqueActivities,operation) \
    ( (This)->lpVtbl->GetRecentUserActivitiesAsync(This,maxUniqueActivities,operation) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_GetSessionHistoryItemsForUserActivityAsync(This,activityId,startTime,operation) \
    ( (This)->lpVtbl->GetSessionHistoryItemsForUserActivityAsync(This,activityId,startTime,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics";
/* [object, uuid("C8C005AB-198D-4D80-ABB2-C9775EC4A729"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDefault )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_GetDefault(This,result) \
    ( (This)->lpVtbl->GetDefault(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics2[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2";
/* [object, uuid("8E87DE30-AA4F-4624-9AD0-D40F3BA0317C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *DisableAutoSessionCreation )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This
        );
    HRESULT ( STDMETHODCALLTYPE *TryGetForWebAccount )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSecurity_CCredentials_CIWebAccount * account,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_DisableAutoSessionCreation(This) \
    ( (This)->lpVtbl->DisableAutoSessionCreation(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_TryGetForWebAccount(This,account,result) \
    ( (This)->lpVtbl->TryGetForWebAccount(This,account,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityChannelStatics3[] = L"Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3";
/* [object, uuid("53BC4DDB-BBDF-5984-802A-5305874E205C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForUser )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSystem_CIUser * user,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannel * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_GetForUser(This,user,result) \
    ( (This)->lpVtbl->GetForUser(This,user,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityChannelStatics3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityContentInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityContentInfo[] = L"Windows.ApplicationModel.UserActivities.IUserActivityContentInfo";
/* [object, uuid("B399E5AD-137F-409D-822D-E1AF27CE08DC"), contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ToJson )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_ToJson(This,result) \
    ( (This)->lpVtbl->ToJson(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityContentInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityContentInfoStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics";
/* [object, uuid("9988C34B-0386-4BC9-968A-8200B004144F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *FromJson )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics * This,
        /* [in] */__RPC__in HSTRING value,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfo * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_FromJson(This,value,result) \
    ( (This)->lpVtbl->FromJson(This,value,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityContentInfoStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityFactory[] = L"Windows.ApplicationModel.UserActivities.IUserActivityFactory";
/* [object, uuid("7C385758-361D-4A67-8A3B-34CA2978F9A3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateWithActivityId )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory * This,
        /* [in] */__RPC__in HSTRING activityId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactoryVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_CreateWithActivityId(This,activityId,value) \
    ( (This)->lpVtbl->CreateWithActivityId(This,activityId,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequest
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequest[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequest";
/* [object, uuid("A0EF6355-CF35-4FF0-8833-50CB4B72E06D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *SetUserActivity )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * activity
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_SetUserActivity(This,activity) \
    ( (This)->lpVtbl->SetUserActivity(This,activity) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequestManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequestManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequestManager[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequestManager";
/* [object, uuid("0C30BE4E-903D-48D6-82D4-4043ED57791B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_UserActivityRequested )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CApplicationModel__CUserActivities__CUserActivityRequestManager_Windows__CApplicationModel__CUserActivities__CUserActivityRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_UserActivityRequested )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_add_UserActivityRequested(This,handler,token) \
    ( (This)->lpVtbl->add_UserActivityRequested(This,handler,token) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_remove_UserActivityRequested(This,token) \
    ( (This)->lpVtbl->remove_UserActivityRequested(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequestManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequestManagerStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics";
/* [object, uuid("C0392DF1-224A-432C-81E5-0C76B4C4CEFA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManager * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_GetForCurrentView(This,result) \
    ( (This)->lpVtbl->GetForCurrentView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityRequestedEventArgs[] = L"Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs";
/* [object, uuid("A4CC7A4C-8229-4CFD-A3BC-C61D318575A4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Request )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequest * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_get_Request(This,value) \
    ( (This)->lpVtbl->get_Request(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_GetDeferral(This,value) \
    ( (This)->lpVtbl->GetDeferral(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivitySession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivitySession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivitySession[] = L"Windows.ApplicationModel.UserActivities.IUserActivitySession";
/* [object, uuid("AE434D78-24FA-44A3-AD48-6EDA61AA1924"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ActivityId )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_get_ActivityId(This,value) \
    ( (This)->lpVtbl->get_ActivityId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivitySessionHistoryItem[] = L"Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem";
/* [object, uuid("E8D59BD3-3E5D-49FD-98D7-6DA97521E255"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UserActivity )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartTime )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EndTime )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CDateTime * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItemVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_get_UserActivity(This,value) \
    ( (This)->lpVtbl->get_UserActivity(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_get_StartTime(This,value) \
    ( (This)->lpVtbl->get_StartTime(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_get_EndTime(This,value) \
    ( (This)->lpVtbl->get_EndTime(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivitySessionHistoryItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivity
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityStatics[] = L"Windows.ApplicationModel.UserActivities.IUserActivityStatics";
/* [object, uuid("8C8FD333-0E09-47F6-9AC7-95CF5C39367B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *TryParseFromJson )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
        /* [in] */__RPC__in HSTRING json,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivity * * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryParseFromJsonArray )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
        /* [in] */__RPC__in HSTRING json,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CApplicationModel__CUserActivities__CUserActivity * * result
        );
    HRESULT ( STDMETHODCALLTYPE *ToJsonArray )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CApplicationModel__CUserActivities__CUserActivity * activities,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_TryParseFromJson(This,json,result) \
    ( (This)->lpVtbl->TryParseFromJson(This,json,result) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_TryParseFromJsonArray(This,json,result) \
    ( (This)->lpVtbl->TryParseFromJsonArray(This,json,result) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_ToJsonArray(This,activities,result) \
    ( (This)->lpVtbl->ToJsonArray(This,activities,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityVisualElements
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityVisualElements
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements[] = L"Windows.ApplicationModel.UserActivities.IUserActivityVisualElements";
/* [object, uuid("94757513-262F-49EF-BBBF-9B75D2E85250"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElementsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayText )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DisplayText )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Description )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Description )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BackgroundColor )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BackgroundColor )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Attribution )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Attribution )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityAttribution * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Content )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CShell_CIAdaptiveCard * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Content )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CShell_CIAdaptiveCard * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElementsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElementsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_get_DisplayText(This,value) \
    ( (This)->lpVtbl->get_DisplayText(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_put_DisplayText(This,value) \
    ( (This)->lpVtbl->put_DisplayText(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_get_Description(This,value) \
    ( (This)->lpVtbl->get_Description(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_put_Description(This,value) \
    ( (This)->lpVtbl->put_Description(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_get_BackgroundColor(This,value) \
    ( (This)->lpVtbl->get_BackgroundColor(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_put_BackgroundColor(This,value) \
    ( (This)->lpVtbl->put_BackgroundColor(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_get_Attribution(This,value) \
    ( (This)->lpVtbl->get_Attribution(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_put_Attribution(This,value) \
    ( (This)->lpVtbl->put_Attribution(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_put_Content(This,value) \
    ( (This)->lpVtbl->put_Content(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_get_Content(This,value) \
    ( (This)->lpVtbl->get_Content(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.UserActivities.UserActivityVisualElements
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_UserActivities_IUserActivityVisualElements2[] = L"Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2";
/* [object, uuid("CAAE7FC7-3EEF-4359-825C-9D51B9220DE3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AttributionDisplayText )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AttributionDisplayText )(
        __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2 * This,
        /* [in] */__RPC__in HSTRING value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2Vtbl;

interface __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_get_AttributionDisplayText(This,value) \
    ( (This)->lpVtbl->get_AttributionDisplayText(This,value) )

#define __x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_put_AttributionDisplayText(This,value) \
    ( (This)->lpVtbl->put_AttributionDisplayText(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CUserActivities_CIUserActivityVisualElements2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivity
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.ApplicationModel.UserActivities.IUserActivityFactory interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivity ** Default Interface **
 *    Windows.ApplicationModel.UserActivities.IUserActivity2
 *    Windows.ApplicationModel.UserActivities.IUserActivity3
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivity_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivity_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivity[] = L"Windows.ApplicationModel.UserActivities.UserActivity";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityAttribution
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Type can be activated via the Windows.ApplicationModel.UserActivities.IUserActivityAttributionFactory interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityAttribution ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityAttribution_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityAttribution_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityAttribution[] = L"Windows.ApplicationModel.UserActivities.UserActivityAttribution";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics3 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics2 interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityChannelStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityChannel ** Default Interface **
 *    Windows.ApplicationModel.UserActivities.IUserActivityChannel2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityChannel_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityChannel_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityChannel[] = L"Windows.ApplicationModel.UserActivities.UserActivityChannel";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityContentInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityContentInfoStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityContentInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityContentInfo_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityContentInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityContentInfo[] = L"Windows.ApplicationModel.UserActivities.UserActivityContentInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityRequest ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequest_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequest_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityRequest[] = L"Windows.ApplicationModel.UserActivities.UserActivityRequest";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityRequestManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.UserActivities.IUserActivityRequestManagerStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityRequestManager ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestManager_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityRequestManager[] = L"Windows.ApplicationModel.UserActivities.UserActivityRequestManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityRequestedEventArgs[] = L"Windows.ApplicationModel.UserActivities.UserActivityRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivitySession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivitySession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySession_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivitySession[] = L"Windows.ApplicationModel.UserActivities.UserActivitySession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivitySessionHistoryItem ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySessionHistoryItem_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivitySessionHistoryItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivitySessionHistoryItem[] = L"Windows.ApplicationModel.UserActivities.UserActivitySessionHistoryItem";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.ApplicationModel.UserActivities.UserActivityVisualElements
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.UserActivities.IUserActivityVisualElements ** Default Interface **
 *    Windows.ApplicationModel.UserActivities.IUserActivityVisualElements2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityVisualElements_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_UserActivities_UserActivityVisualElements_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_UserActivities_UserActivityVisualElements[] = L"Windows.ApplicationModel.UserActivities.UserActivityVisualElements";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eapplicationmodel2Euseractivities_p_h__

#endif // __windows2Eapplicationmodel2Euseractivities_h__
