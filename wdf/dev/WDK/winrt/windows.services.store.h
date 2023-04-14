/* Header file automatically generated from windows.services.store.idl */
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
#ifndef __windows2Eservices2Estore_h__
#define __windows2Eservices2Estore_h__
#ifndef __windows2Eservices2Estore_p_h__
#define __windows2Eservices2Estore_p_h__


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

#if !defined(WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION)
#define WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION 0x40000
#endif // defined(WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION)

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
#include "Windows.ApplicationModel.h"
#include "Windows.System.h"
#include "Windows.Web.Http.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreAcquireLicenseResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult ABI::Windows::Services::Store::IStoreAcquireLicenseResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreAppLicense;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense ABI::Windows::Services::Store::IStoreAppLicense

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreAppLicense2;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 ABI::Windows::Services::Store::IStoreAppLicense2

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreAvailability;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability ABI::Windows::Services::Store::IStoreAvailability

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreCanAcquireLicenseResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreCollectionData;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData ABI::Windows::Services::Store::IStoreCollectionData

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreConsumableResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult ABI::Windows::Services::Store::IStoreConsumableResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreContext;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext ABI::Windows::Services::Store::IStoreContext

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreContext2;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2 ABI::Windows::Services::Store::IStoreContext2

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreContext3;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3 ABI::Windows::Services::Store::IStoreContext3

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreContext4;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4 ABI::Windows::Services::Store::IStoreContext4

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreContextStatics;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics ABI::Windows::Services::Store::IStoreContextStatics

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreImage_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreImage_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreImage;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreImage ABI::Windows::Services::Store::IStoreImage

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreImage_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreLicense;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense ABI::Windows::Services::Store::IStoreLicense

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePackageInstallOptions;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions ABI::Windows::Services::Store::IStorePackageInstallOptions

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePackageLicense;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense ABI::Windows::Services::Store::IStorePackageLicense

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePackageUpdate;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate ABI::Windows::Services::Store::IStorePackageUpdate

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePackageUpdateResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult ABI::Windows::Services::Store::IStorePackageUpdateResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePackageUpdateResult2;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 ABI::Windows::Services::Store::IStorePackageUpdateResult2

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePrice_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePrice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePrice;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePrice ABI::Windows::Services::Store::IStorePrice

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePrice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreProduct;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct ABI::Windows::Services::Store::IStoreProduct

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreProductOptions;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions ABI::Windows::Services::Store::IStoreProductOptions

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreProductPagedQueryResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult ABI::Windows::Services::Store::IStoreProductPagedQueryResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreProductQueryResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult ABI::Windows::Services::Store::IStoreProductQueryResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreProductResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult ABI::Windows::Services::Store::IStoreProductResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePurchaseProperties;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties ABI::Windows::Services::Store::IStorePurchaseProperties

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePurchasePropertiesFactory;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory ABI::Windows::Services::Store::IStorePurchasePropertiesFactory

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStorePurchaseResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult ABI::Windows::Services::Store::IStorePurchaseResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreQueueItem;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem ABI::Windows::Services::Store::IStoreQueueItem

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreQueueItem2;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 ABI::Windows::Services::Store::IStoreQueueItem2

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreQueueItemCompletedEventArgs;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs ABI::Windows::Services::Store::IStoreQueueItemCompletedEventArgs

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreQueueItemStatus;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus ABI::Windows::Services::Store::IStoreQueueItemStatus

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreRateAndReviewResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult ABI::Windows::Services::Store::IStoreRateAndReviewResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreRequestHelperStatics;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics ABI::Windows::Services::Store::IStoreRequestHelperStatics

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreSendRequestResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult ABI::Windows::Services::Store::IStoreSendRequestResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreSendRequestResult2;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 ABI::Windows::Services::Store::IStoreSendRequestResult2

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSku_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSku_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreSku;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreSku ABI::Windows::Services::Store::IStoreSku

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSku_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreSubscriptionInfo;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo ABI::Windows::Services::Store::IStoreSubscriptionInfo

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreUninstallStorePackageResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult ABI::Windows::Services::Store::IStoreUninstallStorePackageResult

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                interface IStoreVideo;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo ABI::Windows::Services::Store::IStoreVideo

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreLicense;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#define DEF___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("33eefc64-ef0c-5c8d-b620-476edf7df799"))
IKeyValuePair<HSTRING,ABI::Windows::Services::Store::StoreLicense*> : IKeyValuePair_impl<HSTRING,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreLicense*, ABI::Windows::Services::Store::IStoreLicense*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.Services.Store.StoreLicense>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IKeyValuePair<HSTRING,ABI::Windows::Services::Store::StoreLicense*> __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t;
#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>
//#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#define DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("a1509348-6522-5062-ae86-cf595475926d"))
IIterator<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense*> : IIterator_impl<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.Services.Store.StoreLicense>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense*> __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t;
#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::__FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>*>
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#define DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("ca8ba445-6f4d-5da9-95ee-42cf118def63"))
IIterable<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense*> : IIterable_impl<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.Services.Store.StoreLicense>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense*> __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t;
#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::__FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>*>
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreProduct;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#define DEF___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("0e89a311-437a-5957-9593-8ed64511545b"))
IKeyValuePair<HSTRING,ABI::Windows::Services::Store::StoreProduct*> : IKeyValuePair_impl<HSTRING,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProduct*, ABI::Windows::Services::Store::IStoreProduct*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.Services.Store.StoreProduct>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IKeyValuePair<HSTRING,ABI::Windows::Services::Store::StoreProduct*> __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t;
#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>
//#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#define DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("0edb142c-9d04-532b-81e9-4c84ab09b34b"))
IIterator<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct*> : IIterator_impl<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.Services.Store.StoreProduct>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct*> __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t;
#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::__FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>*>
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#define DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("78a33722-abfb-57c0-853f-5616a3ab8d57"))
IIterable<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct*> : IIterable_impl<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.Services.Store.StoreProduct>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct*> __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t;
#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::__FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>*>
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreAvailability;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStoreAvailability_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStoreAvailability_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("50511ccb-089e-5b73-bb4a-4d1ef77b8f0f"))
IIterator<ABI::Windows::Services::Store::StoreAvailability*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAvailability*, ABI::Windows::Services::Store::IStoreAvailability*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StoreAvailability>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Services::Store::StoreAvailability*> __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_t;
#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStoreAvailability_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreAvailability*>
//#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreAvailability*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStoreAvailability_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStoreAvailability_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStoreAvailability_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("c58de1a0-25de-578b-bb69-e0a26d67b203"))
IIterable<ABI::Windows::Services::Store::StoreAvailability*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAvailability*, ABI::Windows::Services::Store::IStoreAvailability*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StoreAvailability>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Services::Store::StoreAvailability*> __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_t;
#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStoreAvailability_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreAvailability*>
//#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreAvailability*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStoreAvailability_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreImage;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStoreImage_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStoreImage_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("fbe076f6-c3d2-5df7-839f-012ac0f951c5"))
IIterator<ABI::Windows::Services::Store::StoreImage*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreImage*, ABI::Windows::Services::Store::IStoreImage*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StoreImage>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Services::Store::StoreImage*> __FIIterator_1_Windows__CServices__CStore__CStoreImage_t;
#define __FIIterator_1_Windows__CServices__CStore__CStoreImage ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStoreImage_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStoreImage ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreImage*>
//#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreImage*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStoreImage_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStoreImage_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStoreImage_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b2da6de8-ad55-56ce-8754-2c96f4fe1c2e"))
IIterable<ABI::Windows::Services::Store::StoreImage*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreImage*, ABI::Windows::Services::Store::IStoreImage*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StoreImage>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Services::Store::StoreImage*> __FIIterable_1_Windows__CServices__CStore__CStoreImage_t;
#define __FIIterable_1_Windows__CServices__CStore__CStoreImage ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStoreImage_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStoreImage ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreImage*>
//#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreImage*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStoreImage_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePackageUpdate;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b75dd77b-87ca-5956-8902-84e9ffc97d83"))
IIterator<ABI::Windows::Services::Store::StorePackageUpdate*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageUpdate*, ABI::Windows::Services::Store::IStorePackageUpdate*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StorePackageUpdate>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Services::Store::StorePackageUpdate*> __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_t;
#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStorePackageUpdate*>
//#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStorePackageUpdate*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6b076c51-849e-5ec5-aed5-9b0585591902"))
IIterable<ABI::Windows::Services::Store::StorePackageUpdate*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageUpdate*, ABI::Windows::Services::Store::IStorePackageUpdate*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StorePackageUpdate>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Services::Store::StorePackageUpdate*> __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_t;
#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStorePackageUpdate*>
//#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStorePackageUpdate*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                struct StorePackageUpdateStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6181d84f-f731-57b8-9a6b-8a12fcd58d04"))
IIterator<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> : IIterator_impl<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StorePackageUpdateStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t;
#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::StorePackageUpdateStatus>
//#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::StorePackageUpdateStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE */





#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("60832223-7eb4-5cd7-8340-f5077173d364"))
IIterable<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> : IIterable_impl<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StorePackageUpdateStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t;
#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::StorePackageUpdateStatus>
//#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::StorePackageUpdateStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE */



namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreQueueItem;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("907dd469-85b9-52e7-b52f-7310a44745ef"))
IIterator<ABI::Windows::Services::Store::StoreQueueItem*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreQueueItem*, ABI::Windows::Services::Store::IStoreQueueItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StoreQueueItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Services::Store::StoreQueueItem*> __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_t;
#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreQueueItem*>
//#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreQueueItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("68eb92e6-3cc6-5259-9a05-bd7f8d9fb8da"))
IIterable<ABI::Windows::Services::Store::StoreQueueItem*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreQueueItem*, ABI::Windows::Services::Store::IStoreQueueItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StoreQueueItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Services::Store::StoreQueueItem*> __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_t;
#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreQueueItem*>
//#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreQueueItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreSku;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStoreSku_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStoreSku_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("365cde92-7fe3-59d5-b8f8-8f05acf50947"))
IIterator<ABI::Windows::Services::Store::StoreSku*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreSku*, ABI::Windows::Services::Store::IStoreSku*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StoreSku>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Services::Store::StoreSku*> __FIIterator_1_Windows__CServices__CStore__CStoreSku_t;
#define __FIIterator_1_Windows__CServices__CStore__CStoreSku ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStoreSku_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStoreSku ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreSku*>
//#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreSku*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStoreSku_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStoreSku_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStoreSku_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("522d34ef-4b5a-5b44-a046-7a16051d011e"))
IIterable<ABI::Windows::Services::Store::StoreSku*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreSku*, ABI::Windows::Services::Store::IStoreSku*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StoreSku>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Services::Store::StoreSku*> __FIIterable_1_Windows__CServices__CStore__CStoreSku_t;
#define __FIIterable_1_Windows__CServices__CStore__CStoreSku ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStoreSku_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStoreSku ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreSku*>
//#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreSku*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStoreSku_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreVideo;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CServices__CStore__CStoreVideo_USE
#define DEF___FIIterator_1_Windows__CServices__CStore__CStoreVideo_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("91b0b554-a537-5e22-b39f-6a935d0bef45"))
IIterator<ABI::Windows::Services::Store::StoreVideo*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreVideo*, ABI::Windows::Services::Store::IStoreVideo*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Services.Store.StoreVideo>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Services::Store::StoreVideo*> __FIIterator_1_Windows__CServices__CStore__CStoreVideo_t;
#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CServices__CStore__CStoreVideo_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreVideo*>
//#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Services::Store::IStoreVideo*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CServices__CStore__CStoreVideo_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CServices__CStore__CStoreVideo_USE
#define DEF___FIIterable_1_Windows__CServices__CStore__CStoreVideo_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("46be61e4-7173-565e-aed5-4a2152f1ce69"))
IIterable<ABI::Windows::Services::Store::StoreVideo*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreVideo*, ABI::Windows::Services::Store::IStoreVideo*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Services.Store.StoreVideo>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Services::Store::StoreVideo*> __FIIterable_1_Windows__CServices__CStore__CStoreVideo_t;
#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CServices__CStore__CStoreVideo_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreVideo*>
//#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Services::Store::IStoreVideo*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CServices__CStore__CStoreVideo_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#define DEF___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7d0d74f5-4020-54aa-9f3d-0f17127acddf"))
IMapView<HSTRING,ABI::Windows::Services::Store::StoreLicense*> : IMapView_impl<HSTRING,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreLicense*, ABI::Windows::Services::Store::IStoreLicense*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMapView`2<String, Windows.Services.Store.StoreLicense>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMapView<HSTRING,ABI::Windows::Services::Store::StoreLicense*> __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t;
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::__FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense ABI::Windows::Foundation::Collections::IMapView<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>
//#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_t ABI::Windows::Foundation::Collections::IMapView<HSTRING,ABI::Windows::Services::Store::IStoreLicense*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#define DEF___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("dbaac6e5-61a4-5c88-b5d8-3a3e161c3e4a"))
IMapView<HSTRING,ABI::Windows::Services::Store::StoreProduct*> : IMapView_impl<HSTRING,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProduct*, ABI::Windows::Services::Store::IStoreProduct*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMapView`2<String, Windows.Services.Store.StoreProduct>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMapView<HSTRING,ABI::Windows::Services::Store::StoreProduct*> __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t;
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::__FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct ABI::Windows::Foundation::Collections::IMapView<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>
//#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_t ABI::Windows::Foundation::Collections::IMapView<HSTRING,ABI::Windows::Services::Store::IStoreProduct*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("01e5f751-8c50-52cb-abc2-e9862402c78a"))
IVectorView<ABI::Windows::Services::Store::StoreAvailability*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAvailability*, ABI::Windows::Services::Store::IStoreAvailability*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreAvailability>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Services::Store::StoreAvailability*> __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreAvailability*>
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreAvailability*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStoreImage_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStoreImage_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7e1ceace-82bd-5db3-8f35-9bf0c88ef839"))
IVectorView<ABI::Windows::Services::Store::StoreImage*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreImage*, ABI::Windows::Services::Store::IStoreImage*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreImage>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Services::Store::StoreImage*> __FIVectorView_1_Windows__CServices__CStore__CStoreImage_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStoreImage_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreImage*>
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreImage*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStoreImage_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("971c3ea6-4388-5a38-ae13-4929b6d6d780"))
IVectorView<ABI::Windows::Services::Store::StorePackageUpdate*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageUpdate*, ABI::Windows::Services::Store::IStorePackageUpdate*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StorePackageUpdate>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Services::Store::StorePackageUpdate*> __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStorePackageUpdate*>
//#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStorePackageUpdate*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("68e2f036-4982-55e3-8c0f-9bf4e69aa45a"))
IVectorView<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> : IVectorView_impl<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StorePackageUpdateStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<struct ABI::Windows::Services::Store::StorePackageUpdateStatus> __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::StorePackageUpdateStatus>
//#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::StorePackageUpdateStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_USE */




#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b2d3e99f-d3ac-577d-b977-fdb667d20def"))
IVectorView<ABI::Windows::Services::Store::StoreQueueItem*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreQueueItem*, ABI::Windows::Services::Store::IStoreQueueItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreQueueItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Services::Store::StoreQueueItem*> __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreQueueItem*>
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreQueueItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStoreSku_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStoreSku_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("407c4593-063d-5c9b-b8e0-949fe1387963"))
IVectorView<ABI::Windows::Services::Store::StoreSku*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreSku*, ABI::Windows::Services::Store::IStoreSku*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreSku>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Services::Store::StoreSku*> __FIVectorView_1_Windows__CServices__CStore__CStoreSku_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStoreSku_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreSku*>
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreSku*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStoreSku_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CServices__CStore__CStoreVideo_USE
#define DEF___FIVectorView_1_Windows__CServices__CStore__CStoreVideo_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6e31fca5-119e-5799-a51b-cd6addecd870"))
IVectorView<ABI::Windows::Services::Store::StoreVideo*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreVideo*, ABI::Windows::Services::Store::IStoreVideo*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreVideo>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Services::Store::StoreVideo*> __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_t;
#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CServices__CStore__CStoreVideo_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreVideo*>
//#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreVideo*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CServices__CStore__CStoreVideo_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePackageUpdateResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#define DEF___FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("961260f1-7352-5edf-9666-1f9a0a8ee477"))
IAsyncOperationProgressHandler<ABI::Windows::Services::Store::StorePackageUpdateResult*,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> : IAsyncOperationProgressHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageUpdateResult*, ABI::Windows::Services::Store::IStorePackageUpdateResult*>,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationProgressHandler`2<Windows.Services.Store.StorePackageUpdateResult, Windows.Services.Store.StorePackageUpdateStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationProgressHandler<ABI::Windows::Services::Store::StorePackageUpdateResult*,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t;
#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::__FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::IAsyncOperationProgressHandler<ABI::Windows::Services::Store::IStorePackageUpdateResult*,ABI::Windows::Services::Store::StorePackageUpdateStatus>
//#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t ABI::Windows::Foundation::IAsyncOperationProgressHandler<ABI::Windows::Services::Store::IStorePackageUpdateResult*,ABI::Windows::Services::Store::StorePackageUpdateStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#define DEF___FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b3be0c8b-ef1d-56dc-8547-4da06ea563df"))
IAsyncOperationWithProgressCompletedHandler<ABI::Windows::Services::Store::StorePackageUpdateResult*,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> : IAsyncOperationWithProgressCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageUpdateResult*, ABI::Windows::Services::Store::IStorePackageUpdateResult*>,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationWithProgressCompletedHandler`2<Windows.Services.Store.StorePackageUpdateResult, Windows.Services.Store.StorePackageUpdateStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationWithProgressCompletedHandler<ABI::Windows::Services::Store::StorePackageUpdateResult*,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t;
#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::__FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::IAsyncOperationWithProgressCompletedHandler<ABI::Windows::Services::Store::IStorePackageUpdateResult*,ABI::Windows::Services::Store::StorePackageUpdateStatus>
//#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t ABI::Windows::Foundation::IAsyncOperationWithProgressCompletedHandler<ABI::Windows::Services::Store::IStorePackageUpdateResult*,ABI::Windows::Services::Store::StorePackageUpdateStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#define DEF___FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("42c436ca-51f7-50b2-8fe4-7b754062e6eb"))
IAsyncOperationWithProgress<ABI::Windows::Services::Store::StorePackageUpdateResult*,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> : IAsyncOperationWithProgress_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageUpdateResult*, ABI::Windows::Services::Store::IStorePackageUpdateResult*>,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperationWithProgress`2<Windows.Services.Store.StorePackageUpdateResult, Windows.Services.Store.StorePackageUpdateStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationWithProgress<ABI::Windows::Services::Store::StorePackageUpdateResult*,struct ABI::Windows::Services::Store::StorePackageUpdateStatus> __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t;
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::__FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus ABI::Windows::Foundation::IAsyncOperationWithProgress<ABI::Windows::Services::Store::IStorePackageUpdateResult*,ABI::Windows::Services::Store::StorePackageUpdateStatus>
//#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_t ABI::Windows::Foundation::IAsyncOperationWithProgress<ABI::Windows::Services::Store::IStorePackageUpdateResult*,ABI::Windows::Services::Store::StorePackageUpdateStatus>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#define DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("f8491bcd-2db5-58e0-8c47-44e6eb10c12d"))
IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate*> : IAsyncOperationCompletedHandler_impl<__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StorePackageUpdate>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate*> __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t;
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStorePackageUpdate*>*>
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStorePackageUpdate*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#define DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("0ac66c33-45b8-546b-aaaf-d58d62a4c5c5"))
IAsyncOperation<__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate*> : IAsyncOperation_impl<__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StorePackageUpdate>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<__FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate*> __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t;
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::__FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStorePackageUpdate*>*>
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStorePackageUpdate*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE
#define DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("776b0864-b93d-5669-a75d-70a29325e919"))
IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem*> : IAsyncOperationCompletedHandler_impl<__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreQueueItem>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem*> __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t;
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreQueueItem*>*>
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreQueueItem*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE
#define DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("1346377d-4d6f-5999-9a6e-9c8fbf6f38a2"))
IAsyncOperation<__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem*> : IAsyncOperation_impl<__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Foundation.Collections.IVectorView`1<Windows.Services.Store.StoreQueueItem>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<__FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem*> __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t;
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::__FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreQueueItem*>*>
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Services::Store::IStoreQueueItem*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreAcquireLicenseResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("6987c97c-2c19-5f44-b5ac-37393f3c1a4a"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreAcquireLicenseResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAcquireLicenseResult*, ABI::Windows::Services::Store::IStoreAcquireLicenseResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreAcquireLicenseResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreAcquireLicenseResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreAcquireLicenseResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreAcquireLicenseResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("dd6c4705-a76c-528e-99a5-cdd13197d4cf"))
IAsyncOperation<ABI::Windows::Services::Store::StoreAcquireLicenseResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAcquireLicenseResult*, ABI::Windows::Services::Store::IStoreAcquireLicenseResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreAcquireLicenseResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreAcquireLicenseResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreAcquireLicenseResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreAcquireLicenseResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreAppLicense;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ceff1e09-e506-50ad-a908-52038c256552"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreAppLicense*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAppLicense*, ABI::Windows::Services::Store::IStoreAppLicense*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreAppLicense>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreAppLicense*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreAppLicense*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreAppLicense*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3866370b-afc6-5d01-84c2-4574628de539"))
IAsyncOperation<ABI::Windows::Services::Store::StoreAppLicense*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreAppLicense*, ABI::Windows::Services::Store::IStoreAppLicense*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreAppLicense>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreAppLicense*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreAppLicense*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreAppLicense*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreCanAcquireLicenseResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("572a21d0-7150-50ba-a558-d91dffec1a24"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreCanAcquireLicenseResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreCanAcquireLicenseResult*, ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreCanAcquireLicenseResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreCanAcquireLicenseResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("71ae9f6e-0d10-5bdb-b441-9312e3d2efc2"))
IAsyncOperation<ABI::Windows::Services::Store::StoreCanAcquireLicenseResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreCanAcquireLicenseResult*, ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreCanAcquireLicenseResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreCanAcquireLicenseResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreCanAcquireLicenseResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreConsumableResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3f2bb178-3c4e-56ed-86a5-ad13797cfbfd"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreConsumableResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreConsumableResult*, ABI::Windows::Services::Store::IStoreConsumableResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreConsumableResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreConsumableResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreConsumableResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreConsumableResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("873c497b-c3f7-5657-b921-3e58ce48ee50"))
IAsyncOperation<ABI::Windows::Services::Store::StoreConsumableResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreConsumableResult*, ABI::Windows::Services::Store::IStoreConsumableResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreConsumableResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreConsumableResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreConsumableResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreConsumableResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreProductPagedQueryResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e786321f-b791-5e38-8bc4-98cb287d1085"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreProductPagedQueryResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProductPagedQueryResult*, ABI::Windows::Services::Store::IStoreProductPagedQueryResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreProductPagedQueryResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreProductPagedQueryResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreProductPagedQueryResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreProductPagedQueryResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3079e7db-1ba4-5b9e-856a-6576bf7f9c8a"))
IAsyncOperation<ABI::Windows::Services::Store::StoreProductPagedQueryResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProductPagedQueryResult*, ABI::Windows::Services::Store::IStoreProductPagedQueryResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreProductPagedQueryResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreProductPagedQueryResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreProductPagedQueryResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreProductPagedQueryResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreProductQueryResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("02f4a42c-0458-58d6-923c-b44ba8ef2222"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreProductQueryResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProductQueryResult*, ABI::Windows::Services::Store::IStoreProductQueryResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreProductQueryResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreProductQueryResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreProductQueryResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreProductQueryResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("9699e7bb-ea1f-5e03-9439-c80e6977b711"))
IAsyncOperation<ABI::Windows::Services::Store::StoreProductQueryResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProductQueryResult*, ABI::Windows::Services::Store::IStoreProductQueryResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreProductQueryResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreProductQueryResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreProductQueryResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreProductQueryResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreProductResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("eb93e936-d515-5414-9d15-f050c0b8f521"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreProductResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProductResult*, ABI::Windows::Services::Store::IStoreProductResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreProductResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreProductResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreProductResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreProductResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("9e61e86b-6afb-50ae-afc1-c59f545108dd"))
IAsyncOperation<ABI::Windows::Services::Store::StoreProductResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreProductResult*, ABI::Windows::Services::Store::IStoreProductResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreProductResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreProductResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreProductResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreProductResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePurchaseResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("1d9f89ee-2fce-54e6-a0a9-52d00c52cc3a"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StorePurchaseResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePurchaseResult*, ABI::Windows::Services::Store::IStorePurchaseResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StorePurchaseResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StorePurchaseResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStorePurchaseResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStorePurchaseResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("33d8cc30-78f5-5f81-aa2d-a4fa2a3b1c68"))
IAsyncOperation<ABI::Windows::Services::Store::StorePurchaseResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePurchaseResult*, ABI::Windows::Services::Store::IStorePurchaseResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StorePurchaseResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StorePurchaseResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStorePurchaseResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStorePurchaseResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreRateAndReviewResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ee12d599-9dbd-5e46-a46f-0223b8492761"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreRateAndReviewResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreRateAndReviewResult*, ABI::Windows::Services::Store::IStoreRateAndReviewResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreRateAndReviewResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreRateAndReviewResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreRateAndReviewResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreRateAndReviewResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("844673ec-3402-5a20-becf-e92c3f9681ea"))
IAsyncOperation<ABI::Windows::Services::Store::StoreRateAndReviewResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreRateAndReviewResult*, ABI::Windows::Services::Store::IStoreRateAndReviewResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreRateAndReviewResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreRateAndReviewResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreRateAndReviewResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreRateAndReviewResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreSendRequestResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7800b2a3-bbbc-5a11-8c35-d2bde5489e81"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreSendRequestResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreSendRequestResult*, ABI::Windows::Services::Store::IStoreSendRequestResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreSendRequestResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreSendRequestResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreSendRequestResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreSendRequestResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2acdffe8-259c-5eae-93c1-13a23c74dfee"))
IAsyncOperation<ABI::Windows::Services::Store::StoreSendRequestResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreSendRequestResult*, ABI::Windows::Services::Store::IStoreSendRequestResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreSendRequestResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreSendRequestResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreSendRequestResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreSendRequestResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreUninstallStorePackageResult;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c4de9fb6-1fd9-5229-8818-ba65751db046"))
IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreUninstallStorePackageResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreUninstallStorePackageResult*, ABI::Windows::Services::Store::IStoreUninstallStorePackageResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Services.Store.StoreUninstallStorePackageResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::StoreUninstallStorePackageResult*> __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreUninstallStorePackageResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Services::Store::IStoreUninstallStorePackageResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_USE
#define DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("55aa82fd-ce55-550a-95ec-0554b1915208"))
IAsyncOperation<ABI::Windows::Services::Store::StoreUninstallStorePackageResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreUninstallStorePackageResult*, ABI::Windows::Services::Store::IStoreUninstallStorePackageResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Services.Store.StoreUninstallStorePackageResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Services::Store::StoreUninstallStorePackageResult*> __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_t;
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreUninstallStorePackageResult*>
//#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Services::Store::IStoreUninstallStorePackageResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreContext;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d5a00ac7-082d-547c-a04b-2540c1cde97a"))
ITypedEventHandler<ABI::Windows::Services::Store::StoreContext*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreContext*, ABI::Windows::Services::Store::IStoreContext*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Services.Store.StoreContext, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Services::Store::StoreContext*,IInspectable*> __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStoreContext*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStoreContext*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePackageLicense;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("6c59d637-2970-5f64-9511-d39ac245bc94"))
ITypedEventHandler<ABI::Windows::Services::Store::StorePackageLicense*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StorePackageLicense*, ABI::Windows::Services::Store::IStorePackageLicense*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Services.Store.StorePackageLicense, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Services::Store::StorePackageLicense*,IInspectable*> __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStorePackageLicense*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStorePackageLicense*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("f8ae3690-f9db-57e8-843e-244c0a6a13e0"))
ITypedEventHandler<ABI::Windows::Services::Store::StoreQueueItem*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreQueueItem*, ABI::Windows::Services::Store::IStoreQueueItem*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Services.Store.StoreQueueItem, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Services::Store::StoreQueueItem*,IInspectable*> __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStoreQueueItem*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStoreQueueItem*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreQueueItemCompletedEventArgs;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2bac2880-78fd-5cbe-8271-7d583e4ec2c4"))
ITypedEventHandler<ABI::Windows::Services::Store::StoreQueueItem*,ABI::Windows::Services::Store::StoreQueueItemCompletedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreQueueItem*, ABI::Windows::Services::Store::IStoreQueueItem*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Services::Store::StoreQueueItemCompletedEventArgs*, ABI::Windows::Services::Store::IStoreQueueItemCompletedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Services.Store.StoreQueueItem, Windows.Services.Store.StoreQueueItemCompletedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Services::Store::StoreQueueItem*,ABI::Windows::Services::Store::StoreQueueItemCompletedEventArgs*> __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStoreQueueItem*,ABI::Windows::Services::Store::IStoreQueueItemCompletedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Services::Store::IStoreQueueItem*,ABI::Windows::Services::Store::IStoreQueueItemCompletedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_USE */


#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


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





namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            class Package;
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CApplicationModel_CIPackage_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CIPackage_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            interface IPackage;
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CIPackage ABI::Windows::ApplicationModel::IPackage

#endif // ____x_ABI_CWindows_CApplicationModel_CIPackage_FWD_DEFINED__




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
        namespace Web {
            namespace Http {
                
                typedef enum HttpStatusCode : int HttpStatusCode;
                
            } /* Http */
        } /* Web */
    } /* Windows */} /* ABI */





namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreCanLicenseStatus : int StoreCanLicenseStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreConsumableStatus : int StoreConsumableStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreDurationUnit : int StoreDurationUnit;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StorePackageUpdateState : int StorePackageUpdateState;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StorePurchaseStatus : int StorePurchaseStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreQueueItemExtendedState : int StoreQueueItemExtendedState;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreQueueItemKind : int StoreQueueItemKind;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreQueueItemState : int StoreQueueItemState;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreRateAndReviewStatus : int StoreRateAndReviewStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef enum StoreUninstallStorePackageStatus : int StoreUninstallStorePackageStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                
                typedef struct StorePackageUpdateStatus StorePackageUpdateStatus;
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */













































namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreCollectionData;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */






namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePackageInstallOptions;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */





namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePrice;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreProductOptions;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */





namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StorePurchaseProperties;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */





namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreQueueItemStatus;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */






namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                class StoreSubscriptionInfo;
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */













/*
 *
 * Struct Windows.Services.Store.StoreCanLicenseStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreCanLicenseStatus : int
                {
                    StoreCanLicenseStatus_NotLicensableToUser = 0,
                    StoreCanLicenseStatus_Licensable = 1,
                    StoreCanLicenseStatus_LicenseActionNotApplicableToProduct = 2,
                    StoreCanLicenseStatus_NetworkError = 3,
                    StoreCanLicenseStatus_ServerError = 4,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreConsumableStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreConsumableStatus : int
                {
                    StoreConsumableStatus_Succeeded = 0,
                    StoreConsumableStatus_InsufficentQuantity = 1,
                    StoreConsumableStatus_NetworkError = 2,
                    StoreConsumableStatus_ServerError = 3,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StoreDurationUnit
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreDurationUnit : int
                {
                    StoreDurationUnit_Minute = 0,
                    StoreDurationUnit_Hour = 1,
                    StoreDurationUnit_Day = 2,
                    StoreDurationUnit_Week = 3,
                    StoreDurationUnit_Month = 4,
                    StoreDurationUnit_Year = 5,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StorePackageUpdateState
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StorePackageUpdateState : int
                {
                    StorePackageUpdateState_Pending = 0,
                    StorePackageUpdateState_Downloading = 1,
                    StorePackageUpdateState_Deploying = 2,
                    StorePackageUpdateState_Completed = 3,
                    StorePackageUpdateState_Canceled = 4,
                    StorePackageUpdateState_OtherError = 5,
                    StorePackageUpdateState_ErrorLowBattery = 6,
                    StorePackageUpdateState_ErrorWiFiRecommended = 7,
                    StorePackageUpdateState_ErrorWiFiRequired = 8,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StorePurchaseStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StorePurchaseStatus : int
                {
                    StorePurchaseStatus_Succeeded = 0,
                    StorePurchaseStatus_AlreadyPurchased = 1,
                    StorePurchaseStatus_NotPurchased = 2,
                    StorePurchaseStatus_NetworkError = 3,
                    StorePurchaseStatus_ServerError = 4,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StoreQueueItemExtendedState
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreQueueItemExtendedState : int
                {
                    StoreQueueItemExtendedState_ActivePending = 0,
                    StoreQueueItemExtendedState_ActiveStarting = 1,
                    StoreQueueItemExtendedState_ActiveAcquiringLicense = 2,
                    StoreQueueItemExtendedState_ActiveDownloading = 3,
                    StoreQueueItemExtendedState_ActiveRestoringData = 4,
                    StoreQueueItemExtendedState_ActiveInstalling = 5,
                    StoreQueueItemExtendedState_Completed = 6,
                    StoreQueueItemExtendedState_Canceled = 7,
                    StoreQueueItemExtendedState_Paused = 8,
                    StoreQueueItemExtendedState_Error = 9,
                    StoreQueueItemExtendedState_PausedPackagesInUse = 10,
                    StoreQueueItemExtendedState_PausedLowBattery = 11,
                    StoreQueueItemExtendedState_PausedWiFiRecommended = 12,
                    StoreQueueItemExtendedState_PausedWiFiRequired = 13,
                    StoreQueueItemExtendedState_PausedReadyToInstall = 14,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreQueueItemKind
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreQueueItemKind : int
                {
                    StoreQueueItemKind_Install = 0,
                    StoreQueueItemKind_Update = 1,
                    StoreQueueItemKind_Repair = 2,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreQueueItemState
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreQueueItemState : int
                {
                    StoreQueueItemState_Active = 0,
                    StoreQueueItemState_Completed = 1,
                    StoreQueueItemState_Canceled = 2,
                    StoreQueueItemState_Error = 3,
                    StoreQueueItemState_Paused = 4,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreRateAndReviewStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreRateAndReviewStatus : int
                {
                    StoreRateAndReviewStatus_Succeeded = 0,
                    StoreRateAndReviewStatus_CanceledByUser = 1,
                    StoreRateAndReviewStatus_NetworkError = 2,
                    StoreRateAndReviewStatus_Error = 3,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Services.Store.StoreUninstallStorePackageStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [v1_enum, contract] */
                enum StoreUninstallStorePackageStatus : int
                {
                    StoreUninstallStorePackageStatus_Succeeded = 0,
                    StoreUninstallStorePackageStatus_CanceledByUser = 1,
                    StoreUninstallStorePackageStatus_NetworkError = 2,
                    StoreUninstallStorePackageStatus_UninstallNotApplicable = 3,
                    StoreUninstallStorePackageStatus_Error = 4,
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StorePackageUpdateStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [contract] */
                struct StorePackageUpdateStatus
                {
                    HSTRING PackageFamilyName;
                    UINT64 PackageDownloadSizeInBytes;
                    UINT64 PackageBytesDownloaded;
                    DOUBLE PackageDownloadProgress;
                    DOUBLE TotalDownloadProgress;
                    ABI::Windows::Services::Store::StorePackageUpdateState PackageUpdateState;
                };
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAcquireLicenseResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAcquireLicenseResult[] = L"Windows.Services.Store.IStoreAcquireLicenseResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("FBD7946D-F040-4CB3-9A39-29BCECDBE22D"), exclusiveto, contract] */
                MIDL_INTERFACE("FBD7946D-F040-4CB3-9A39-29BCECDBE22D")
                IStoreAcquireLicenseResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StorePackageLicense(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStorePackageLicense * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreAcquireLicenseResult=_uuidof(IStoreAcquireLicenseResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreAppLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAppLicense
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAppLicense[] = L"Windows.Services.Store.IStoreAppLicense";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("F389F9DE-73C0-45CE-9BAB-B2FE3E5EAFD3"), exclusiveto, contract] */
                MIDL_INTERFACE("F389F9DE-73C0-45CE-9BAB-B2FE3E5EAFD3")
                IStoreAppLicense : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SkuStoreId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsActive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsTrial(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExpirationDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AddOnLicenses(
                        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrialTimeRemaining(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsTrialOwnedByThisUser(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrialUniqueId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreAppLicense=_uuidof(IStoreAppLicense);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAppLicense;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreAppLicense2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAppLicense
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAppLicense2[] = L"Windows.Services.Store.IStoreAppLicense2";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("B4666E91-4443-40B3-993F-28904435BDC6"), exclusiveto, contract] */
                MIDL_INTERFACE("B4666E91-4443-40B3-993F-28904435BDC6")
                IStoreAppLicense2 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsDiscLicense(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreAppLicense2=_uuidof(IStoreAppLicense2);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreAvailability
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAvailability
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAvailability[] = L"Windows.Services.Store.IStoreAvailability";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("FA060325-0FFD-4493-AD43-F1F9918F69FA"), exclusiveto, contract] */
                MIDL_INTERFACE("FA060325-0FFD-4493-AD43-F1F9918F69FA")
                IStoreAvailability : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StoreId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EndDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Price(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStorePrice * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseWithPurchasePropertiesAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStorePurchaseProperties * storePurchaseProperties,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreAvailability=_uuidof(IStoreAvailability);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAvailability;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreCanAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreCanAcquireLicenseResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreCanAcquireLicenseResult[] = L"Windows.Services.Store.IStoreCanAcquireLicenseResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("3A693DB3-0088-482F-86D5-BD46522663AD"), exclusiveto, contract] */
                MIDL_INTERFACE("3A693DB3-0088-482F-86D5-BD46522663AD")
                IStoreCanAcquireLicenseResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LicensableSku(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreCanLicenseStatus * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreCanAcquireLicenseResult=_uuidof(IStoreCanAcquireLicenseResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreCollectionData
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreCollectionData
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreCollectionData[] = L"Windows.Services.Store.IStoreCollectionData";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("8AA4C3B3-5BB3-441A-2AB4-4DAB73D5CE67"), exclusiveto, contract] */
                MIDL_INTERFACE("8AA4C3B3-5BB3-441A-2AB4-4DAB73D5CE67")
                IStoreCollectionData : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsTrial(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CampaignId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeveloperOfferId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AcquiredDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EndDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrialTimeRemaining(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreCollectionData=_uuidof(IStoreCollectionData);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreCollectionData;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreConsumableResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreConsumableResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreConsumableResult[] = L"Windows.Services.Store.IStoreConsumableResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("EA5DAB72-6A00-4052-BE5B-BFDAB4433352"), exclusiveto, contract] */
                MIDL_INTERFACE("EA5DAB72-6A00-4052-BE5B-BFDAB4433352")
                IStoreConsumableResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreConsumableStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrackingId(
                        /* [retval, out] */__RPC__out GUID * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BalanceRemaining(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreConsumableResult=_uuidof(IStoreConsumableResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreContext
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext[] = L"Windows.Services.Store.IStoreContext";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("AC98B6BE-F4FD-4912-BABD-5035E5E8BCAB"), exclusiveto, contract] */
                MIDL_INTERFACE("AC98B6BE-F4FD-4912-BABD-5035E5E8BCAB")
                IStoreContext : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_User(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::System::IUser * * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_OfflineLicensesChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_OfflineLicensesChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCustomerPurchaseIdAsync(
                        /* [in] */__RPC__in HSTRING serviceTicket,
                        /* [in] */__RPC__in HSTRING publisherUserId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCustomerCollectionsIdAsync(
                        /* [in] */__RPC__in HSTRING serviceTicket,
                        /* [in] */__RPC__in HSTRING publisherUserId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAppLicenseAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetStoreProductForCurrentAppAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetStoreProductsAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAssociatedStoreProductsAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAssociatedStoreProductsWithPagingAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [in] */UINT32 maxItemsToRetrievePerPage,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetUserCollectionAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetUserCollectionWithPagingAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [in] */UINT32 maxItemsToRetrievePerPage,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ReportConsumableFulfillmentAsync(
                        /* [in] */__RPC__in HSTRING productStoreId,
                        /* [in] */UINT32 quantity,
                        /* [in] */GUID trackingId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetConsumableBalanceRemainingAsync(
                        /* [in] */__RPC__in HSTRING productStoreId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE AcquireStoreLicenseForOptionalPackageAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::IPackage * optionalPackage,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseAsync(
                        /* [in] */__RPC__in HSTRING storeId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseWithPurchasePropertiesAsync(
                        /* [in] */__RPC__in HSTRING storeId,
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStorePurchaseProperties * storePurchaseProperties,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAppAndOptionalStorePackageUpdatesAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestDownloadStorePackageUpdatesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackageUpdatesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackagesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreContext=_uuidof(IStoreContext);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreContext2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext2[] = L"Windows.Services.Store.IStoreContext2";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("18BC54DA-7BD9-452C-9116-3BBD06FFC63A"), exclusiveto, contract] */
                MIDL_INTERFACE("18BC54DA-7BD9-452C-9116-3BBD06FFC63A")
                IStoreContext2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE FindStoreProductForPackageAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::IPackage * package,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreContext2=_uuidof(IStoreContext2);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.Services.Store.IStoreContext3
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext3[] = L"Windows.Services.Store.IStoreContext3";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("E26226CA-1A01-4730-85A6-ECC896E4AE38"), exclusiveto, contract] */
                MIDL_INTERFACE("E26226CA-1A01-4730-85A6-ECC896E4AE38")
                IStoreContext3 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanSilentlyDownloadStorePackageUpdates(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TrySilentDownloadStorePackageUpdatesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TrySilentDownloadAndInstallStorePackageUpdatesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CanAcquireStoreLicenseForOptionalPackageAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::IPackage * optionalPackage,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CanAcquireStoreLicenseAsync(
                        /* [in] */__RPC__in HSTRING productStoreId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE GetStoreProductsWithOptionsAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStoreProductOptions * storeProductOptions,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAssociatedStoreQueueItemsAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetStoreQueueItemsAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStorePackageInstallOptions * storePackageInstallOptions,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DownloadAndInstallStorePackagesAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestUninstallStorePackageAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::IPackage * package,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestUninstallStorePackageByStoreIdAsync(
                        /* [in] */__RPC__in HSTRING storeId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UninstallStorePackageAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::IPackage * package,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UninstallStorePackageByStoreIdAsync(
                        /* [in] */__RPC__in HSTRING storeId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreContext3=_uuidof(IStoreContext3);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext3;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext3_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreContext4
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext4[] = L"Windows.Services.Store.IStoreContext4";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("AF9C6F69-BEA1-4BF4-8E74-AE03E206C6B0"), exclusiveto, contract] */
                MIDL_INTERFACE("AF9C6F69-BEA1-4BF4-8E74-AE03E206C6B0")
                IStoreContext4 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE RequestRateAndReviewAppAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetInstallOrderForAssociatedStoreQueueItemsAsync(
                        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * items,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreContext4=_uuidof(IStoreContext4);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext4;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext4_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreContextStatics
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContextStatics[] = L"Windows.Services.Store.IStoreContextStatics";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("9C06EE5F-15C0-4E72-9330-D6191CEBD19C"), exclusiveto, contract] */
                MIDL_INTERFACE("9C06EE5F-15C0-4E72-9330-D6191CEBD19C")
                IStoreContextStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDefault(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreContext * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetForUser(
                        /* [in] */__RPC__in_opt ABI::Windows::System::IUser * user,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreContext * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreContextStatics=_uuidof(IStoreContextStatics);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContextStatics;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreImage
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreImage
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreImage_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreImage_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreImage[] = L"Windows.Services.Store.IStoreImage";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("081FD248-ADB4-4B64-A993-784789926ED5"), exclusiveto, contract] */
                MIDL_INTERFACE("081FD248-ADB4-4B64-A993-784789926ED5")
                IStoreImage : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ImagePurposeTag(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Width(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Height(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Caption(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreImage=_uuidof(IStoreImage);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreImage;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreImage_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreLicense
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreLicense_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreLicense[] = L"Windows.Services.Store.IStoreLicense";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("26DC9579-4C4F-4F30-BC89-649F60E36055"), exclusiveto, contract] */
                MIDL_INTERFACE("26DC9579-4C4F-4F30-BC89-649F60E36055")
                IStoreLicense : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SkuStoreId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsActive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExpirationDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InAppOfferToken(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreLicense=_uuidof(IStoreLicense);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreLicense;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreLicense_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageInstallOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageInstallOptions
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageInstallOptions[] = L"Windows.Services.Store.IStorePackageInstallOptions";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("1D3D630C-0CCD-44DD-8C59-80810A729973"), exclusiveto, contract] */
                MIDL_INTERFACE("1D3D630C-0CCD-44DD-8C59-80810A729973")
                IStorePackageInstallOptions : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AllowForcedAppRestart(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AllowForcedAppRestart(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePackageInstallOptions=_uuidof(IStorePackageInstallOptions);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStorePackageLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageLicense
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Foundation.IClosable
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageLicense[] = L"Windows.Services.Store.IStorePackageLicense";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("0C465714-14E1-4973-BD14-F77724271E99"), exclusiveto, contract] */
                MIDL_INTERFACE("0C465714-14E1-4973-BD14-F77724271E99")
                IStorePackageLicense : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LicenseLost(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LicenseLost(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Package(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::IPackage * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsValid(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ReleaseLicense(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePackageLicense=_uuidof(IStorePackageLicense);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageLicense;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageUpdate
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageUpdate
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageUpdate[] = L"Windows.Services.Store.IStorePackageUpdate";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("140FA150-3CBF-4A35-B91F-48271C31B072"), exclusiveto, contract] */
                MIDL_INTERFACE("140FA150-3CBF-4A35-B91F-48271C31B072")
                IStorePackageUpdate : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Package(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::IPackage * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Mandatory(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePackageUpdate=_uuidof(IStorePackageUpdate);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageUpdateResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageUpdateResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageUpdateResult[] = L"Windows.Services.Store.IStorePackageUpdateResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("E79142ED-61F9-4893-B4FE-CF191603AF7B"), exclusiveto, contract] */
                MIDL_INTERFACE("E79142ED-61F9-4893-B4FE-CF191603AF7B")
                IStorePackageUpdateResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OverallState(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StorePackageUpdateState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StorePackageUpdateStatuses(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePackageUpdateResult=_uuidof(IStorePackageUpdateResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageUpdateResult2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageUpdateResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageUpdateResult2[] = L"Windows.Services.Store.IStorePackageUpdateResult2";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("071D012E-BC62-4F2E-87EA-99D801AEAF98"), exclusiveto, contract] */
                MIDL_INTERFACE("071D012E-BC62-4F2E-87EA-99D801AEAF98")
                IStorePackageUpdateResult2 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StoreQueueItems(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePackageUpdateResult2=_uuidof(IStorePackageUpdateResult2);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStorePrice
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePrice
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePrice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePrice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePrice[] = L"Windows.Services.Store.IStorePrice";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("55BA94C4-15F1-407C-8F06-006380F4DF0B"), exclusiveto, contract] */
                MIDL_INTERFACE("55BA94C4-15F1-407C-8F06-006380F4DF0B")
                IStorePrice : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_FormattedBasePrice(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_FormattedPrice(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsOnSale(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SaleEndDate(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CurrencyCode(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_FormattedRecurrencePrice(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePrice=_uuidof(IStorePrice);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePrice;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePrice_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProduct
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProduct
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProduct_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProduct[] = L"Windows.Services.Store.IStoreProduct";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("320E2C52-D760-450A-A42B-67D1E901AC90"), exclusiveto, contract] */
                MIDL_INTERFACE("320E2C52-D760-450A-A42B-67D1E901AC90")
                IStoreProduct : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StoreId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Language(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Title(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Description(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ProductKind(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HasDigitalDownload(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Keywords(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Images(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreImage * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Videos(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Skus(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreSku * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInUserCollection(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Price(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStorePrice * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LinkUri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetIsAnySkuInstalledAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseWithPurchasePropertiesAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStorePurchaseProperties * storePurchaseProperties,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InAppOfferToken(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreProduct=_uuidof(IStoreProduct);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProduct;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProduct_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProductOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductOptions
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductOptions[] = L"Windows.Services.Store.IStoreProductOptions";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("5B34A0F9-A113-4811-8326-16199C927F31"), exclusiveto, contract] */
                MIDL_INTERFACE("5B34A0F9-A113-4811-8326-16199C927F31")
                IStoreProductOptions : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ActionFilters(
                        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_HSTRING * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreProductOptions=_uuidof(IStoreProductOptions);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductOptions;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreProductPagedQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductPagedQueryResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductPagedQueryResult[] = L"Windows.Services.Store.IStoreProductPagedQueryResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("C92718C5-4DD5-4869-A462-ECC6872E43C5"), exclusiveto, contract] */
                MIDL_INTERFACE("C92718C5-4DD5-4869-A462-ECC6872E43C5")
                IStoreProductPagedQueryResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Products(
                        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HasMoreResults(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetNextAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreProductPagedQueryResult=_uuidof(IStoreProductPagedQueryResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProductQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductQueryResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductQueryResult[] = L"Windows.Services.Store.IStoreProductQueryResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("D805E6C5-D456-4FF6-8049-9076D5165F73"), exclusiveto, contract] */
                MIDL_INTERFACE("D805E6C5-D456-4FF6-8049-9076D5165F73")
                IStoreProductQueryResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Products(
                        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreProductQueryResult=_uuidof(IStoreProductQueryResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProductResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductResult[] = L"Windows.Services.Store.IStoreProductResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("B7674F73-3C87-4EE1-8201-F428359BD3AF"), exclusiveto, contract] */
                MIDL_INTERFACE("B7674F73-3C87-4EE1-8201-F428359BD3AF")
                IStoreProductResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Product(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreProduct * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreProductResult=_uuidof(IStoreProductResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePurchaseProperties
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePurchaseProperties
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePurchaseProperties[] = L"Windows.Services.Store.IStorePurchaseProperties";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("836278F3-FF87-4364-A5B4-FD2153EBE43B"), exclusiveto, contract] */
                MIDL_INTERFACE("836278F3-FF87-4364-A5B4-FD2153EBE43B")
                IStorePurchaseProperties : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Name(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Name(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ExtendedJsonData(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePurchaseProperties=_uuidof(IStorePurchaseProperties);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePurchasePropertiesFactory
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePurchaseProperties
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePurchasePropertiesFactory[] = L"Windows.Services.Store.IStorePurchasePropertiesFactory";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("A768F59E-FEFD-489F-9A17-22A593E68B9D"), exclusiveto, contract] */
                MIDL_INTERFACE("A768F59E-FEFD-489F-9A17-22A593E68B9D")
                IStorePurchasePropertiesFactory : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [in] */__RPC__in HSTRING name,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStorePurchaseProperties * * storePurchaseProperties
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePurchasePropertiesFactory=_uuidof(IStorePurchasePropertiesFactory);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePurchaseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePurchaseResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePurchaseResult[] = L"Windows.Services.Store.IStorePurchaseResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("ADD28552-F96A-463D-A7BB-C20B4FCA6952"), exclusiveto, contract] */
                MIDL_INTERFACE("ADD28552-F96A-463D-A7BB-C20B4FCA6952")
                IStorePurchaseResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StorePurchaseStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStorePurchaseResult=_uuidof(IStorePurchaseResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItem
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItem
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItem[] = L"Windows.Services.Store.IStoreQueueItem";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("56D5C32B-F830-4293-9188-CAD2DCDE7357"), exclusiveto, contract] */
                MIDL_INTERFACE("56D5C32B-F830-4293-9188-CAD2DCDE7357")
                IStoreQueueItem : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ProductId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PackageFamilyName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InstallKind(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreQueueItemKind * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentStatus(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreQueueItemStatus * * result
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Completed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Completed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_StatusChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_StatusChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreQueueItem=_uuidof(IStoreQueueItem);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItem;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItem2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItem
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItem2[] = L"Windows.Services.Store.IStoreQueueItem2";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("69491CA8-1AD4-447C-AD8C-A95035F64D82"), exclusiveto, contract] */
                MIDL_INTERFACE("69491CA8-1AD4-447C-AD8C-A95035F64D82")
                IStoreQueueItem2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CancelInstallAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * action
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE PauseInstallAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * action
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ResumeInstallAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * action
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreQueueItem2=_uuidof(IStoreQueueItem2);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItemCompletedEventArgs
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItemCompletedEventArgs
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItemCompletedEventArgs[] = L"Windows.Services.Store.IStoreQueueItemCompletedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("1247DF6C-B44A-439B-BB07-1D3003D005C2"), exclusiveto, contract] */
                MIDL_INTERFACE("1247DF6C-B44A-439B-BB07-1D3003D005C2")
                IStoreQueueItemCompletedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreQueueItemStatus * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreQueueItemCompletedEventArgs=_uuidof(IStoreQueueItemCompletedEventArgs);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItemStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItemStatus
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItemStatus[] = L"Windows.Services.Store.IStoreQueueItemStatus";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("9BD6796F-9CC3-4EC3-B2EF-7BE433B30174"), exclusiveto, contract] */
                MIDL_INTERFACE("9BD6796F-9CC3-4EC3-B2EF-7BE433B30174")
                IStoreQueueItemStatus : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PackageInstallState(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreQueueItemState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PackageInstallExtendedState(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreQueueItemExtendedState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UpdateStatus(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StorePackageUpdateStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreQueueItemStatus=_uuidof(IStoreQueueItemStatus);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreRateAndReviewResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreRateAndReviewResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreRateAndReviewResult[] = L"Windows.Services.Store.IStoreRateAndReviewResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("9D209D56-A6B5-4121-9B61-EE6D0FBDBDBB"), exclusiveto, contract] */
                MIDL_INTERFACE("9D209D56-A6B5-4121-9B61-EE6D0FBDBDBB")
                IStoreRateAndReviewResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WasUpdated(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreRateAndReviewStatus * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreRateAndReviewResult=_uuidof(IStoreRateAndReviewResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreRequestHelperStatics
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreRequestHelper
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreRequestHelperStatics[] = L"Windows.Services.Store.IStoreRequestHelperStatics";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("6CE5E5F9-A0C9-4B2C-96A6-A171C630038D"), exclusiveto, contract] */
                MIDL_INTERFACE("6CE5E5F9-A0C9-4B2C-96A6-A171C630038D")
                IStoreRequestHelperStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE SendRequestAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStoreContext * context,
                        /* [in] */UINT32 requestKind,
                        /* [in] */__RPC__in HSTRING parametersAsJson,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreRequestHelperStatics=_uuidof(IStoreRequestHelperStatics);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreSendRequestResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSendRequestResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSendRequestResult[] = L"Windows.Services.Store.IStoreSendRequestResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("C73ABE60-8272-4502-8A69-6E75153A4299"), exclusiveto, contract] */
                MIDL_INTERFACE("C73ABE60-8272-4502-8A69-6E75153A4299")
                IStoreSendRequestResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Response(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreSendRequestResult=_uuidof(IStoreSendRequestResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreSendRequestResult2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSendRequestResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSendRequestResult2[] = L"Windows.Services.Store.IStoreSendRequestResult2";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("2901296F-C0B0-49D0-8E8D-AA940AF9C10B"), exclusiveto, contract] */
                MIDL_INTERFACE("2901296F-C0B0-49D0-8E8D-AA940AF9C10B")
                IStoreSendRequestResult2 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HttpStatusCode(
                        /* [retval, out] */__RPC__out ABI::Windows::Web::Http::HttpStatusCode * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreSendRequestResult2=_uuidof(IStoreSendRequestResult2);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.Services.Store.IStoreSku
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSku
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSku_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSku_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSku[] = L"Windows.Services.Store.IStoreSku";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("397E6F55-4440-4F03-863C-91F3FEC83D79"), exclusiveto, contract] */
                MIDL_INTERFACE("397E6F55-4440-4F03-863C-91F3FEC83D79")
                IStoreSku : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StoreId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Language(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Title(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Description(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsTrial(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CustomDeveloperData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Images(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreImage * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Videos(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Availabilities(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Price(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStorePrice * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedJsonData(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInUserCollection(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BundledSkus(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CollectionData(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreCollectionData * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetIsInstalledAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPurchaseWithPurchasePropertiesAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Services::Store::IStorePurchaseProperties * storePurchaseProperties,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsSubscription(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SubscriptionInfo(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreSubscriptionInfo * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreSku=_uuidof(IStoreSku);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSku;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSku_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreSubscriptionInfo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSubscriptionInfo
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSubscriptionInfo[] = L"Windows.Services.Store.IStoreSubscriptionInfo";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("4189776A-0559-43AC-A9C6-3AB0011FB8EB"), exclusiveto, contract] */
                MIDL_INTERFACE("4189776A-0559-43AC-A9C6-3AB0011FB8EB")
                IStoreSubscriptionInfo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BillingPeriod(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BillingPeriodUnit(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreDurationUnit * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HasTrialPeriod(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrialPeriod(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrialPeriodUnit(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreDurationUnit * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreSubscriptionInfo=_uuidof(IStoreSubscriptionInfo);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreUninstallStorePackageResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreUninstallStorePackageResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreUninstallStorePackageResult[] = L"Windows.Services.Store.IStoreUninstallStorePackageResult";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("9FCA39FD-126F-4CDA-B801-1346B8D0A260"), exclusiveto, contract] */
                MIDL_INTERFACE("9FCA39FD-126F-4CDA-B801-1346B8D0A260")
                IStoreUninstallStorePackageResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Services::Store::StoreUninstallStorePackageStatus * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreUninstallStorePackageResult=_uuidof(IStoreUninstallStorePackageResult);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreVideo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreVideo
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreVideo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreVideo[] = L"Windows.Services.Store.IStoreVideo";
namespace ABI {
    namespace Windows {
        namespace Services {
            namespace Store {
                /* [object, uuid("F26CB184-6F5E-4DC2-886C-3C63083C2F94"), exclusiveto, contract] */
                MIDL_INTERFACE("F26CB184-6F5E-4DC2-886C-3C63083C2F94")
                IStoreVideo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_VideoPurposeTag(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Width(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Height(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Caption(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PreviewImage(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Services::Store::IStoreImage * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IStoreVideo=_uuidof(IStoreVideo);
                
            } /* Store */
        } /* Services */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreVideo;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreVideo_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreAcquireLicenseResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreAcquireLicenseResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreAcquireLicenseResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreAcquireLicenseResult[] = L"Windows.Services.Store.StoreAcquireLicenseResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreAppLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreAppLicense ** Default Interface **
 *    Windows.Services.Store.IStoreAppLicense2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreAppLicense_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreAppLicense_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreAppLicense[] = L"Windows.Services.Store.StoreAppLicense";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreAvailability
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreAvailability ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreAvailability_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreAvailability_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreAvailability[] = L"Windows.Services.Store.StoreAvailability";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreCanAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreCanAcquireLicenseResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreCanAcquireLicenseResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreCanAcquireLicenseResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreCanAcquireLicenseResult[] = L"Windows.Services.Store.StoreCanAcquireLicenseResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreCollectionData
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreCollectionData ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreCollectionData_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreCollectionData_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreCollectionData[] = L"Windows.Services.Store.StoreCollectionData";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreConsumableResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreConsumableResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreConsumableResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreConsumableResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreConsumableResult[] = L"Windows.Services.Store.StoreConsumableResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreContext
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Services.Store.IStoreContextStatics interface starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreContext ** Default Interface **
 *    Windows.Services.Store.IStoreContext2
 *    Windows.Services.Store.IStoreContext3
 *    Windows.Services.Store.IStoreContext4
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreContext_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreContext_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreContext[] = L"Windows.Services.Store.StoreContext";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreImage
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreImage ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreImage_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreImage_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreImage[] = L"Windows.Services.Store.StoreImage";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreLicense ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreLicense_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreLicense_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreLicense[] = L"Windows.Services.Store.StoreLicense";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePackageInstallOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 3.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageInstallOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageInstallOptions_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageInstallOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageInstallOptions[] = L"Windows.Services.Store.StorePackageInstallOptions";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StorePackageLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageLicense ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageLicense_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageLicense_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageLicense[] = L"Windows.Services.Store.StorePackageLicense";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePackageUpdate
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageUpdate ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageUpdate_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageUpdate_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageUpdate[] = L"Windows.Services.Store.StorePackageUpdate";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePackageUpdateResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageUpdateResult ** Default Interface **
 *    Windows.Services.Store.IStorePackageUpdateResult2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageUpdateResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageUpdateResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageUpdateResult[] = L"Windows.Services.Store.StorePackageUpdateResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePrice
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePrice ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePrice_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePrice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePrice[] = L"Windows.Services.Store.StorePrice";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProduct
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProduct ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProduct_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProduct_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProduct[] = L"Windows.Services.Store.StoreProduct";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProductOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 3.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductOptions_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductOptions[] = L"Windows.Services.Store.StoreProductOptions";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreProductPagedQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductPagedQueryResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductPagedQueryResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductPagedQueryResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductPagedQueryResult[] = L"Windows.Services.Store.StoreProductPagedQueryResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProductQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductQueryResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductQueryResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductQueryResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductQueryResult[] = L"Windows.Services.Store.StoreProductQueryResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProductResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductResult[] = L"Windows.Services.Store.StoreProductResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePurchaseProperties
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *   Type can be activated via the Windows.Services.Store.IStorePurchasePropertiesFactory interface starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePurchaseProperties ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePurchaseProperties_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePurchaseProperties_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePurchaseProperties[] = L"Windows.Services.Store.StorePurchaseProperties";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePurchaseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePurchaseResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePurchaseResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePurchaseResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePurchaseResult[] = L"Windows.Services.Store.StorePurchaseResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreQueueItem
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreQueueItem ** Default Interface **
 *    Windows.Services.Store.IStoreQueueItem2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreQueueItem_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreQueueItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreQueueItem[] = L"Windows.Services.Store.StoreQueueItem";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreQueueItemCompletedEventArgs
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreQueueItemCompletedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreQueueItemCompletedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreQueueItemCompletedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreQueueItemCompletedEventArgs[] = L"Windows.Services.Store.StoreQueueItemCompletedEventArgs";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreQueueItemStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreQueueItemStatus ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreQueueItemStatus_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreQueueItemStatus_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreQueueItemStatus[] = L"Windows.Services.Store.StoreQueueItemStatus";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreRateAndReviewResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreRateAndReviewResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreRateAndReviewResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreRateAndReviewResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreRateAndReviewResult[] = L"Windows.Services.Store.StoreRateAndReviewResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.Services.Store.StoreRequestHelper
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Services.Store.IStoreRequestHelperStatics interface starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_Services_Store_StoreRequestHelper_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreRequestHelper_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreRequestHelper[] = L"Windows.Services.Store.StoreRequestHelper";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreSendRequestResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreSendRequestResult ** Default Interface **
 *    Windows.Services.Store.IStoreSendRequestResult2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreSendRequestResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreSendRequestResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreSendRequestResult[] = L"Windows.Services.Store.StoreSendRequestResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreSku
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreSku ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreSku_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreSku_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreSku[] = L"Windows.Services.Store.StoreSku";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreSubscriptionInfo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreSubscriptionInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreSubscriptionInfo_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreSubscriptionInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreSubscriptionInfo[] = L"Windows.Services.Store.StoreSubscriptionInfo";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreUninstallStorePackageResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreUninstallStorePackageResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreUninstallStorePackageResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreUninstallStorePackageResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreUninstallStorePackageResult[] = L"Windows.Services.Store.StoreUninstallStorePackageResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreVideo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreVideo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreVideo_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreVideo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreVideo[] = L"Windows.Services.Store.StoreVideo";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreAvailability __x_ABI_CWindows_CServices_CStore_CIStoreAvailability;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreContext __x_ABI_CWindows_CServices_CStore_CIStoreContext;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreContext2 __x_ABI_CWindows_CServices_CStore_CIStoreContext2;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreContext3 __x_ABI_CWindows_CServices_CStore_CIStoreContext3;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreContext4 __x_ABI_CWindows_CServices_CStore_CIStoreContext4;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreImage_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreImage_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreImage __x_ABI_CWindows_CServices_CStore_CIStoreImage;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreImage_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreLicense __x_ABI_CWindows_CServices_CStore_CIStoreLicense;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePrice_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePrice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePrice __x_ABI_CWindows_CServices_CStore_CIStorePrice;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePrice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreProduct __x_ABI_CWindows_CServices_CStore_CIStoreProduct;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreProductResult __x_ABI_CWindows_CServices_CStore_CIStoreProductResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSku_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSku_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreSku __x_ABI_CWindows_CServices_CStore_CIStoreSku;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSku_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_FWD_DEFINED__
#define ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CServices_CStore_CIStoreVideo __x_ABI_CWindows_CServices_CStore_CIStoreVideo;

#endif // ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__)
#define ____FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

typedef interface __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

typedef struct __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Key )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__out HSTRING *key);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreLicense * *value);
    END_INTERFACE
} __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl;

interface __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense
{
    CONST_VTBL struct __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_get_Key(This,key)	\
    ( (This)->lpVtbl -> get_Key(This,key) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__)
#define ____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

typedef interface __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

typedef struct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__out __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl;

interface __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense
{
    CONST_VTBL struct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__)
#define ____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

typedef interface __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

typedef  struct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense **first);

    END_INTERFACE
} __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl;

interface __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense
{
    CONST_VTBL struct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__)
#define ____FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

typedef interface __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

typedef struct __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Key )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__out HSTRING *key);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreProduct * *value);
    END_INTERFACE
} __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl;

interface __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct
{
    CONST_VTBL struct __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_get_Key(This,key)	\
    ( (This)->lpVtbl -> get_Key(This,key) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__)
#define ____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

typedef interface __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

typedef struct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__out __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl;

interface __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct
{
    CONST_VTBL struct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__)
#define ____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

typedef interface __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

typedef  struct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct **first);

    END_INTERFACE
} __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl;

interface __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct
{
    CONST_VTBL struct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStoreAvailability __FIIterator_1_Windows__CServices__CStore__CStoreAvailability;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStoreAvailability;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStoreAvailabilityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreAvailability * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStoreAvailabilityVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStoreAvailability
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStoreAvailabilityVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreAvailability_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStoreAvailability __FIIterable_1_Windows__CServices__CStore__CStoreAvailability;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStoreAvailability;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStoreAvailabilityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreAvailability * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStoreAvailability **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStoreAvailabilityVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStoreAvailability
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStoreAvailabilityVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreAvailability_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStoreImage __FIIterator_1_Windows__CServices__CStore__CStoreImage;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStoreImage;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStoreImageVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreImage * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreImage * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreImage * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStoreImageVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStoreImage
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStoreImageVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreImage_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStoreImage __FIIterable_1_Windows__CServices__CStore__CStoreImage;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStoreImage;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStoreImageVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreImage * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStoreImage **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStoreImageVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStoreImage
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStoreImageVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreImage_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdate **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus;

#if !defined(____FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__



#if !defined(____FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStorePackageUpdateStatus **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStoreQueueItem;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStoreQueueItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStoreQueueItemVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStoreQueueItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStoreQueueItem;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStoreQueueItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStoreQueueItem **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStoreQueueItemVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStoreQueueItemVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStoreSku __FIIterator_1_Windows__CServices__CStore__CStoreSku;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStoreSku;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStoreSkuVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreSku * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreSku * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreSku * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStoreSkuVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStoreSku
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStoreSkuVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreSku_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStoreSku __FIIterable_1_Windows__CServices__CStore__CStoreSku;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStoreSku;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStoreSkuVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreSku * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStoreSku **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStoreSkuVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStoreSku
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStoreSkuVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreSku_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CServices__CStore__CStoreVideo __FIIterator_1_Windows__CServices__CStore__CStoreVideo;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CServices__CStore__CStoreVideo;

typedef struct __FIIterator_1_Windows__CServices__CStore__CStoreVideoVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreVideo * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CServices__CStore__CStoreVideo * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreVideo * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CServices__CStore__CStoreVideoVtbl;

interface __FIIterator_1_Windows__CServices__CStore__CStoreVideo
{
    CONST_VTBL struct __FIIterator_1_Windows__CServices__CStore__CStoreVideoVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CServices__CStore__CStoreVideo_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CServices__CStore__CStoreVideo __FIIterable_1_Windows__CServices__CStore__CStoreVideo;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CServices__CStore__CStoreVideo;

typedef  struct __FIIterable_1_Windows__CServices__CStore__CStoreVideoVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CServices__CStore__CStoreVideo * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CServices__CStore__CStoreVideo **first);

    END_INTERFACE
} __FIIterable_1_Windows__CServices__CStore__CStoreVideoVtbl;

interface __FIIterable_1_Windows__CServices__CStore__CStoreVideo
{
    CONST_VTBL struct __FIIterable_1_Windows__CServices__CStore__CStoreVideoVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CServices__CStore__CStoreVideo_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__)
#define ____FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

typedef interface __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense;

typedef struct __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,/* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,
        /* [in] */ __RPC__in HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreLicense * *value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This, /* [in] */ __RPC__in HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *Split )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * This,/* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense **firstPartition,
        /* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense **secondPartition);
    END_INTERFACE
} __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl;

interface __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense
{
    CONST_VTBL struct __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_Split(This,firstPartition,secondPartition)	\
    ( (This)->lpVtbl -> Split(This,firstPartition,secondPartition) ) 
#endif /* COBJMACROS */


#endif // ____FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__)
#define ____FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

typedef interface __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct;

typedef struct __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,/* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,
        /* [in] */ __RPC__in HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreProduct * *value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This, /* [in] */ __RPC__in HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *Split )(__RPC__in __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * This,/* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct **firstPartition,
        /* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct **secondPartition);
    END_INTERFACE
} __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl;

interface __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct
{
    CONST_VTBL struct __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProductVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 
#define __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_Split(This,firstPartition,secondPartition)	\
    ( (This)->lpVtbl -> Split(This,firstPartition,secondPartition) ) 
#endif /* COBJMACROS */


#endif // ____FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStoreAvailability;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStoreAvailabilityVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
            /* [in] */ __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStoreAvailabilityVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStoreAvailabilityVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStoreAvailability_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStoreImage __FIVectorView_1_Windows__CServices__CStore__CStoreImage;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStoreImage;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStoreImageVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreImage * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
            /* [in] */ __x_ABI_CWindows_CServices_CStore_CIStoreImage * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreImage * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreImage * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStoreImageVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStoreImage
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStoreImageVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreImage_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStoreImage_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
            /* [in] */ __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
            /* [in] */ struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
            /* [in] */ __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStoreSku __FIVectorView_1_Windows__CServices__CStore__CStoreSku;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStoreSku;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStoreSkuVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreSku * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
            /* [in] */ __x_ABI_CWindows_CServices_CStore_CIStoreSku * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreSku * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreSku * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStoreSkuVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStoreSku
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStoreSkuVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreSku_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStoreSku_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CServices__CStore__CStoreVideo __FIVectorView_1_Windows__CServices__CStore__CStoreVideo;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CServices__CStore__CStoreVideo;

typedef struct __FIVectorView_1_Windows__CServices__CStore__CStoreVideoVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreVideo * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
            /* [in] */ __x_ABI_CWindows_CServices_CStore_CIStoreVideo * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CServices_CStore_CIStoreVideo * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CServices__CStore__CStoreVideoVtbl;

interface __FIVectorView_1_Windows__CServices__CStore__CStoreVideo
{
    CONST_VTBL struct __FIVectorView_1_Windows__CServices__CStore__CStoreVideoVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CServices__CStore__CStoreVideo_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CServices__CStore__CStoreVideo_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef interface __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef struct __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus *asyncInfo, /* [in] */ struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus progressInfo);
    END_INTERFACE
} __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl;

interface __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus
{
    CONST_VTBL struct __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_Invoke(This,asyncInfo,progressInfo)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,progressInfo) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Forward declare the async operation.
typedef interface __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef struct __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl;

interface __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus
{
    CONST_VTBL struct __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl *lpVtbl;
};



#ifdef COBJMACROS
#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */



#endif // ____FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus;

typedef struct __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Progress )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Progress )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationProgressHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus **handler);
    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationWithProgressCompletedHandler_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * This, /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * *results);
    END_INTERFACE
} __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl;

interface __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus
{
    CONST_VTBL struct __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_put_Progress(This,handler)	\
    ( (This)->lpVtbl -> put_Progress(This,handler) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_get_Progress(This,handler)	\
    ( (This)->lpVtbl -> get_Progress(This,handler) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */



#endif // ____FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

typedef struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl;

interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate;

typedef struct __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * This, /* [retval][out] */ __RPC__out __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * *results);
    END_INTERFACE
} __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl;

interface __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate
{
    CONST_VTBL struct __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

typedef struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl;

interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem;

typedef struct __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * This, /* [retval][out] */ __RPC__out __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * *results);
    END_INTERFACE
} __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl;

interface __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem
{
    CONST_VTBL struct __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAcquireLicenseResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicenseVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicenseVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicenseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreAppLicense **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicenseVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreConsumableResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductPagedQueryResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductQueryResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreProductResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStorePurchaseResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreRateAndReviewResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreSendRequestResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult;

typedef struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResultVtbl;

interface __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStoreContext * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000



#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

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



#ifndef ____x_ABI_CWindows_CApplicationModel_CIPackage_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CIPackage_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CIPackage __x_ABI_CWindows_CApplicationModel_CIPackage;

#endif // ____x_ABI_CWindows_CApplicationModel_CIPackage_FWD_DEFINED__





typedef struct __x_ABI_CWindows_CFoundation_CDateTime __x_ABI_CWindows_CFoundation_CDateTime;

#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIAsyncAction __x_ABI_CWindows_CFoundation_CIAsyncAction;

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;

#ifndef ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIUriRuntimeClass __x_ABI_CWindows_CFoundation_CIUriRuntimeClass;

#endif // ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CIUser __x_ABI_CWindows_CSystem_CIUser;

#endif // ____x_ABI_CWindows_CSystem_CIUser_FWD_DEFINED__





typedef enum __x_ABI_CWindows_CWeb_CHttp_CHttpStatusCode __x_ABI_CWindows_CWeb_CHttp_CHttpStatusCode;






typedef enum __x_ABI_CWindows_CServices_CStore_CStoreCanLicenseStatus __x_ABI_CWindows_CServices_CStore_CStoreCanLicenseStatus;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreConsumableStatus __x_ABI_CWindows_CServices_CStore_CStoreConsumableStatus;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreDurationUnit __x_ABI_CWindows_CServices_CStore_CStoreDurationUnit;


typedef enum __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateState __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateState;


typedef enum __x_ABI_CWindows_CServices_CStore_CStorePurchaseStatus __x_ABI_CWindows_CServices_CStore_CStorePurchaseStatus;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreQueueItemExtendedState __x_ABI_CWindows_CServices_CStore_CStoreQueueItemExtendedState;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreQueueItemKind __x_ABI_CWindows_CServices_CStore_CStoreQueueItemKind;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreQueueItemState __x_ABI_CWindows_CServices_CStore_CStoreQueueItemState;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreRateAndReviewStatus __x_ABI_CWindows_CServices_CStore_CStoreRateAndReviewStatus;


typedef enum __x_ABI_CWindows_CServices_CStore_CStoreUninstallStorePackageStatus __x_ABI_CWindows_CServices_CStore_CStoreUninstallStorePackageStatus;


typedef struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus;

















































































/*
 *
 * Struct Windows.Services.Store.StoreCanLicenseStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreCanLicenseStatus
{
    StoreCanLicenseStatus_NotLicensableToUser = 0,
    StoreCanLicenseStatus_Licensable = 1,
    StoreCanLicenseStatus_LicenseActionNotApplicableToProduct = 2,
    StoreCanLicenseStatus_NetworkError = 3,
    StoreCanLicenseStatus_ServerError = 4,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreConsumableStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreConsumableStatus
{
    StoreConsumableStatus_Succeeded = 0,
    StoreConsumableStatus_InsufficentQuantity = 1,
    StoreConsumableStatus_NetworkError = 2,
    StoreConsumableStatus_ServerError = 3,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StoreDurationUnit
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreDurationUnit
{
    StoreDurationUnit_Minute = 0,
    StoreDurationUnit_Hour = 1,
    StoreDurationUnit_Day = 2,
    StoreDurationUnit_Week = 3,
    StoreDurationUnit_Month = 4,
    StoreDurationUnit_Year = 5,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StorePackageUpdateState
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateState
{
    StorePackageUpdateState_Pending = 0,
    StorePackageUpdateState_Downloading = 1,
    StorePackageUpdateState_Deploying = 2,
    StorePackageUpdateState_Completed = 3,
    StorePackageUpdateState_Canceled = 4,
    StorePackageUpdateState_OtherError = 5,
    StorePackageUpdateState_ErrorLowBattery = 6,
    StorePackageUpdateState_ErrorWiFiRecommended = 7,
    StorePackageUpdateState_ErrorWiFiRequired = 8,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StorePurchaseStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStorePurchaseStatus
{
    StorePurchaseStatus_Succeeded = 0,
    StorePurchaseStatus_AlreadyPurchased = 1,
    StorePurchaseStatus_NotPurchased = 2,
    StorePurchaseStatus_NetworkError = 3,
    StorePurchaseStatus_ServerError = 4,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Services.Store.StoreQueueItemExtendedState
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreQueueItemExtendedState
{
    StoreQueueItemExtendedState_ActivePending = 0,
    StoreQueueItemExtendedState_ActiveStarting = 1,
    StoreQueueItemExtendedState_ActiveAcquiringLicense = 2,
    StoreQueueItemExtendedState_ActiveDownloading = 3,
    StoreQueueItemExtendedState_ActiveRestoringData = 4,
    StoreQueueItemExtendedState_ActiveInstalling = 5,
    StoreQueueItemExtendedState_Completed = 6,
    StoreQueueItemExtendedState_Canceled = 7,
    StoreQueueItemExtendedState_Paused = 8,
    StoreQueueItemExtendedState_Error = 9,
    StoreQueueItemExtendedState_PausedPackagesInUse = 10,
    StoreQueueItemExtendedState_PausedLowBattery = 11,
    StoreQueueItemExtendedState_PausedWiFiRecommended = 12,
    StoreQueueItemExtendedState_PausedWiFiRequired = 13,
    StoreQueueItemExtendedState_PausedReadyToInstall = 14,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreQueueItemKind
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreQueueItemKind
{
    StoreQueueItemKind_Install = 0,
    StoreQueueItemKind_Update = 1,
    StoreQueueItemKind_Repair = 2,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreQueueItemState
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreQueueItemState
{
    StoreQueueItemState_Active = 0,
    StoreQueueItemState_Completed = 1,
    StoreQueueItemState_Canceled = 2,
    StoreQueueItemState_Error = 3,
    StoreQueueItemState_Paused = 4,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StoreRateAndReviewStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreRateAndReviewStatus
{
    StoreRateAndReviewStatus_Succeeded = 0,
    StoreRateAndReviewStatus_CanceledByUser = 1,
    StoreRateAndReviewStatus_NetworkError = 2,
    StoreRateAndReviewStatus_Error = 3,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Services.Store.StoreUninstallStorePackageStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 */

#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CServices_CStore_CStoreUninstallStorePackageStatus
{
    StoreUninstallStorePackageStatus_Succeeded = 0,
    StoreUninstallStorePackageStatus_CanceledByUser = 1,
    StoreUninstallStorePackageStatus_NetworkError = 2,
    StoreUninstallStorePackageStatus_UninstallNotApplicable = 3,
    StoreUninstallStorePackageStatus_Error = 4,
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.Services.Store.StorePackageUpdateStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

/* [contract] */
struct __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus
{
    HSTRING PackageFamilyName;
    UINT64 PackageDownloadSizeInBytes;
    UINT64 PackageBytesDownloaded;
    DOUBLE PackageDownloadProgress;
    DOUBLE TotalDownloadProgress;
    __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateState PackageUpdateState;
};
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAcquireLicenseResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAcquireLicenseResult[] = L"Windows.Services.Store.IStoreAcquireLicenseResult";
/* [object, uuid("FBD7946D-F040-4CB3-9A39-29BCECDBE22D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StorePackageLicense )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_get_StorePackageLicense(This,value) \
    ( (This)->lpVtbl->get_StorePackageLicense(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAcquireLicenseResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreAppLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAppLicense
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAppLicense[] = L"Windows.Services.Store.IStoreAppLicense";
/* [object, uuid("F389F9DE-73C0-45CE-9BAB-B2FE3E5EAFD3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreAppLicenseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SkuStoreId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsActive )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsTrial )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExpirationDate )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AddOnLicenses )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreLicense * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrialTimeRemaining )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsTrialOwnedByThisUser )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrialUniqueId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreAppLicenseVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreAppLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_SkuStoreId(This,value) \
    ( (This)->lpVtbl->get_SkuStoreId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_IsActive(This,value) \
    ( (This)->lpVtbl->get_IsActive(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_IsTrial(This,value) \
    ( (This)->lpVtbl->get_IsTrial(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_ExpirationDate(This,value) \
    ( (This)->lpVtbl->get_ExpirationDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_AddOnLicenses(This,value) \
    ( (This)->lpVtbl->get_AddOnLicenses(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_TrialTimeRemaining(This,value) \
    ( (This)->lpVtbl->get_TrialTimeRemaining(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_IsTrialOwnedByThisUser(This,value) \
    ( (This)->lpVtbl->get_IsTrialOwnedByThisUser(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_get_TrialUniqueId(This,value) \
    ( (This)->lpVtbl->get_TrialUniqueId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAppLicense;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreAppLicense2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAppLicense
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAppLicense2[] = L"Windows.Services.Store.IStoreAppLicense2";
/* [object, uuid("B4666E91-4443-40B3-993F-28904435BDC6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsDiscLicense )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_get_IsDiscLicense(This,value) \
    ( (This)->lpVtbl->get_IsDiscLicense(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAppLicense2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreAvailability
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreAvailability
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreAvailability[] = L"Windows.Services.Store.IStoreAvailability";
/* [object, uuid("FA060325-0FFD-4493-AD43-F1F9918F69FA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreAvailabilityVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StoreId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EndDate )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Price )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStorePrice * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseWithPurchasePropertiesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreAvailability * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * storePurchaseProperties,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreAvailabilityVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreAvailability
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreAvailabilityVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_get_StoreId(This,value) \
    ( (This)->lpVtbl->get_StoreId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_get_EndDate(This,value) \
    ( (This)->lpVtbl->get_EndDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_get_Price(This,value) \
    ( (This)->lpVtbl->get_Price(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_RequestPurchaseAsync(This,operation) \
    ( (This)->lpVtbl->RequestPurchaseAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreAvailability_RequestPurchaseWithPurchasePropertiesAsync(This,storePurchaseProperties,operation) \
    ( (This)->lpVtbl->RequestPurchaseWithPurchasePropertiesAsync(This,storePurchaseProperties,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreAvailability;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreAvailability_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreCanAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreCanAcquireLicenseResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreCanAcquireLicenseResult[] = L"Windows.Services.Store.IStoreCanAcquireLicenseResult";
/* [object, uuid("3A693DB3-0088-482F-86D5-BD46522663AD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LicensableSku )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreCanLicenseStatus * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_get_LicensableSku(This,value) \
    ( (This)->lpVtbl->get_LicensableSku(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCanAcquireLicenseResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreCollectionData
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreCollectionData
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreCollectionData[] = L"Windows.Services.Store.IStoreCollectionData";
/* [object, uuid("8AA4C3B3-5BB3-441A-2AB4-4DAB73D5CE67"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreCollectionDataVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsTrial )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CampaignId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeveloperOfferId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AcquiredDate )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartDate )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EndDate )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrialTimeRemaining )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreCollectionDataVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreCollectionDataVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_IsTrial(This,value) \
    ( (This)->lpVtbl->get_IsTrial(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_CampaignId(This,value) \
    ( (This)->lpVtbl->get_CampaignId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_DeveloperOfferId(This,value) \
    ( (This)->lpVtbl->get_DeveloperOfferId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_AcquiredDate(This,value) \
    ( (This)->lpVtbl->get_AcquiredDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_StartDate(This,value) \
    ( (This)->lpVtbl->get_StartDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_EndDate(This,value) \
    ( (This)->lpVtbl->get_EndDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_TrialTimeRemaining(This,value) \
    ( (This)->lpVtbl->get_TrialTimeRemaining(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreCollectionData;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreCollectionData_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreConsumableResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreConsumableResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreConsumableResult[] = L"Windows.Services.Store.IStoreConsumableResult";
/* [object, uuid("EA5DAB72-6A00-4052-BE5B-BFDAB4433352"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreConsumableStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrackingId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
        /* [retval, out] */__RPC__out GUID * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BalanceRemaining )(
        __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_get_TrackingId(This,value) \
    ( (This)->lpVtbl->get_TrackingId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_get_BalanceRemaining(This,value) \
    ( (This)->lpVtbl->get_BalanceRemaining(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreConsumableResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreContext
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext[] = L"Windows.Services.Store.IStoreContext";
/* [object, uuid("AC98B6BE-F4FD-4912-BABD-5035E5E8BCAB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreContextVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_User )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSystem_CIUser * * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_OfflineLicensesChanged )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStoreContext_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_OfflineLicensesChanged )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *GetCustomerPurchaseIdAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in HSTRING serviceTicket,
        /* [in] */__RPC__in HSTRING publisherUserId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetCustomerCollectionsIdAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in HSTRING serviceTicket,
        /* [in] */__RPC__in HSTRING publisherUserId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAppLicenseAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAppLicense * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetStoreProductForCurrentAppAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetStoreProductsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAssociatedStoreProductsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAssociatedStoreProductsWithPagingAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [in] */UINT32 maxItemsToRetrievePerPage,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetUserCollectionAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetUserCollectionWithPagingAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [in] */UINT32 maxItemsToRetrievePerPage,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *ReportConsumableFulfillmentAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in HSTRING productStoreId,
        /* [in] */UINT32 quantity,
        /* [in] */GUID trackingId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetConsumableBalanceRemainingAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in HSTRING productStoreId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreConsumableResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *AcquireStoreLicenseForOptionalPackageAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CIPackage * optionalPackage,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreAcquireLicenseResult * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in HSTRING storeId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseWithPurchasePropertiesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in HSTRING storeId,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * storePurchaseProperties,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAppAndOptionalStorePackageUpdatesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdate * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestDownloadStorePackageUpdatesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestDownloadAndInstallStorePackageUpdatesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestDownloadAndInstallStorePackagesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreContextVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreContext
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreContextVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_get_User(This,value) \
    ( (This)->lpVtbl->get_User(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_add_OfflineLicensesChanged(This,handler,token) \
    ( (This)->lpVtbl->add_OfflineLicensesChanged(This,handler,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_remove_OfflineLicensesChanged(This,token) \
    ( (This)->lpVtbl->remove_OfflineLicensesChanged(This,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetCustomerPurchaseIdAsync(This,serviceTicket,publisherUserId,operation) \
    ( (This)->lpVtbl->GetCustomerPurchaseIdAsync(This,serviceTicket,publisherUserId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetCustomerCollectionsIdAsync(This,serviceTicket,publisherUserId,operation) \
    ( (This)->lpVtbl->GetCustomerCollectionsIdAsync(This,serviceTicket,publisherUserId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetAppLicenseAsync(This,operation) \
    ( (This)->lpVtbl->GetAppLicenseAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetStoreProductForCurrentAppAsync(This,operation) \
    ( (This)->lpVtbl->GetStoreProductForCurrentAppAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetStoreProductsAsync(This,productKinds,storeIds,operation) \
    ( (This)->lpVtbl->GetStoreProductsAsync(This,productKinds,storeIds,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetAssociatedStoreProductsAsync(This,productKinds,operation) \
    ( (This)->lpVtbl->GetAssociatedStoreProductsAsync(This,productKinds,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetAssociatedStoreProductsWithPagingAsync(This,productKinds,maxItemsToRetrievePerPage,operation) \
    ( (This)->lpVtbl->GetAssociatedStoreProductsWithPagingAsync(This,productKinds,maxItemsToRetrievePerPage,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetUserCollectionAsync(This,productKinds,operation) \
    ( (This)->lpVtbl->GetUserCollectionAsync(This,productKinds,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetUserCollectionWithPagingAsync(This,productKinds,maxItemsToRetrievePerPage,operation) \
    ( (This)->lpVtbl->GetUserCollectionWithPagingAsync(This,productKinds,maxItemsToRetrievePerPage,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_ReportConsumableFulfillmentAsync(This,productStoreId,quantity,trackingId,operation) \
    ( (This)->lpVtbl->ReportConsumableFulfillmentAsync(This,productStoreId,quantity,trackingId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetConsumableBalanceRemainingAsync(This,productStoreId,operation) \
    ( (This)->lpVtbl->GetConsumableBalanceRemainingAsync(This,productStoreId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_AcquireStoreLicenseForOptionalPackageAsync(This,optionalPackage,operation) \
    ( (This)->lpVtbl->AcquireStoreLicenseForOptionalPackageAsync(This,optionalPackage,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_RequestPurchaseAsync(This,storeId,operation) \
    ( (This)->lpVtbl->RequestPurchaseAsync(This,storeId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_RequestPurchaseWithPurchasePropertiesAsync(This,storeId,storePurchaseProperties,operation) \
    ( (This)->lpVtbl->RequestPurchaseWithPurchasePropertiesAsync(This,storeId,storePurchaseProperties,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_GetAppAndOptionalStorePackageUpdatesAsync(This,operation) \
    ( (This)->lpVtbl->GetAppAndOptionalStorePackageUpdatesAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_RequestDownloadStorePackageUpdatesAsync(This,storePackageUpdates,operation) \
    ( (This)->lpVtbl->RequestDownloadStorePackageUpdatesAsync(This,storePackageUpdates,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_RequestDownloadAndInstallStorePackageUpdatesAsync(This,storePackageUpdates,operation) \
    ( (This)->lpVtbl->RequestDownloadAndInstallStorePackageUpdatesAsync(This,storePackageUpdates,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext_RequestDownloadAndInstallStorePackagesAsync(This,storeIds,operation) \
    ( (This)->lpVtbl->RequestDownloadAndInstallStorePackagesAsync(This,storeIds,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreContext2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext2[] = L"Windows.Services.Store.IStoreContext2";
/* [object, uuid("18BC54DA-7BD9-452C-9116-3BBD06FFC63A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreContext2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *FindStoreProductForPackageAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CIPackage * package,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductResult * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreContext2Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreContext2
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreContext2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext2_FindStoreProductForPackageAsync(This,productKinds,package,operation) \
    ( (This)->lpVtbl->FindStoreProductForPackageAsync(This,productKinds,package,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.Services.Store.IStoreContext3
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext3[] = L"Windows.Services.Store.IStoreContext3";
/* [object, uuid("E26226CA-1A01-4730-85A6-ECC896E4AE38"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreContext3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanSilentlyDownloadStorePackageUpdates )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *TrySilentDownloadStorePackageUpdatesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TrySilentDownloadAndInstallStorePackageUpdatesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStorePackageUpdate * storePackageUpdates,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CanAcquireStoreLicenseForOptionalPackageAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CIPackage * optionalPackage,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CanAcquireStoreLicenseAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in HSTRING productStoreId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreCanAcquireLicenseResult * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *GetStoreProductsWithOptionsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * productKinds,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * storeProductOptions,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductQueryResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetAssociatedStoreQueueItemsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetStoreQueueItemsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * storePackageInstallOptions,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *DownloadAndInstallStorePackagesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * storeIds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperationWithProgress_2_Windows__CServices__CStore__CStorePackageUpdateResult_Windows__CServices__CStore__CStorePackageUpdateStatus * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestUninstallStorePackageAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CIPackage * package,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *RequestUninstallStorePackageByStoreIdAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in HSTRING storeId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *UninstallStorePackageAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CIPackage * package,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *UninstallStorePackageByStoreIdAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext3 * This,
        /* [in] */__RPC__in HSTRING storeId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreUninstallStorePackageResult * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreContext3Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreContext3
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreContext3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_get_CanSilentlyDownloadStorePackageUpdates(This,value) \
    ( (This)->lpVtbl->get_CanSilentlyDownloadStorePackageUpdates(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_TrySilentDownloadStorePackageUpdatesAsync(This,storePackageUpdates,operation) \
    ( (This)->lpVtbl->TrySilentDownloadStorePackageUpdatesAsync(This,storePackageUpdates,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_TrySilentDownloadAndInstallStorePackageUpdatesAsync(This,storePackageUpdates,operation) \
    ( (This)->lpVtbl->TrySilentDownloadAndInstallStorePackageUpdatesAsync(This,storePackageUpdates,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_CanAcquireStoreLicenseForOptionalPackageAsync(This,optionalPackage,operation) \
    ( (This)->lpVtbl->CanAcquireStoreLicenseForOptionalPackageAsync(This,optionalPackage,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_CanAcquireStoreLicenseAsync(This,productStoreId,operation) \
    ( (This)->lpVtbl->CanAcquireStoreLicenseAsync(This,productStoreId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_GetStoreProductsWithOptionsAsync(This,productKinds,storeIds,storeProductOptions,operation) \
    ( (This)->lpVtbl->GetStoreProductsWithOptionsAsync(This,productKinds,storeIds,storeProductOptions,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_GetAssociatedStoreQueueItemsAsync(This,operation) \
    ( (This)->lpVtbl->GetAssociatedStoreQueueItemsAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_GetStoreQueueItemsAsync(This,storeIds,operation) \
    ( (This)->lpVtbl->GetStoreQueueItemsAsync(This,storeIds,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(This,storeIds,storePackageInstallOptions,operation) \
    ( (This)->lpVtbl->RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(This,storeIds,storePackageInstallOptions,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_DownloadAndInstallStorePackagesAsync(This,storeIds,operation) \
    ( (This)->lpVtbl->DownloadAndInstallStorePackagesAsync(This,storeIds,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_RequestUninstallStorePackageAsync(This,package,operation) \
    ( (This)->lpVtbl->RequestUninstallStorePackageAsync(This,package,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_RequestUninstallStorePackageByStoreIdAsync(This,storeId,operation) \
    ( (This)->lpVtbl->RequestUninstallStorePackageByStoreIdAsync(This,storeId,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_UninstallStorePackageAsync(This,package,operation) \
    ( (This)->lpVtbl->UninstallStorePackageAsync(This,package,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext3_UninstallStorePackageByStoreIdAsync(This,storeId,operation) \
    ( (This)->lpVtbl->UninstallStorePackageByStoreIdAsync(This,storeId,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext3;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext3_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreContext4
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContext4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContext4[] = L"Windows.Services.Store.IStoreContext4";
/* [object, uuid("AF9C6F69-BEA1-4BF4-8E74-AE03E206C6B0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreContext4Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *RequestRateAndReviewAppAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreRateAndReviewResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *SetInstallOrderForAssociatedStoreQueueItemsAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContext4 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CServices__CStore__CStoreQueueItem * items,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreContext4Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreContext4
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreContext4Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_RequestRateAndReviewAppAsync(This,operation) \
    ( (This)->lpVtbl->RequestRateAndReviewAppAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContext4_SetInstallOrderForAssociatedStoreQueueItemsAsync(This,items,operation) \
    ( (This)->lpVtbl->SetInstallOrderForAssociatedStoreQueueItemsAsync(This,items,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContext4;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContext4_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreContextStatics
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreContext
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreContextStatics[] = L"Windows.Services.Store.IStoreContextStatics";
/* [object, uuid("9C06EE5F-15C0-4E72-9330-D6191CEBD19C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreContextStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDefault )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreContext * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetForUser )(
        __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CSystem_CIUser * user,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreContext * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreContextStaticsVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreContextStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_GetDefault(This,value) \
    ( (This)->lpVtbl->GetDefault(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_GetForUser(This,user,value) \
    ( (This)->lpVtbl->GetForUser(This,user,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreContextStatics;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreContextStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreImage
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreImage
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreImage_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreImage_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreImage[] = L"Windows.Services.Store.IStoreImage";
/* [object, uuid("081FD248-ADB4-4B64-A993-784789926ED5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreImageVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreImage * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreImage * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ImagePurposeTag )(
        __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Width )(
        __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Height )(
        __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Caption )(
        __x_ABI_CWindows_CServices_CStore_CIStoreImage * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreImageVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreImage
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreImageVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_get_ImagePurposeTag(This,value) \
    ( (This)->lpVtbl->get_ImagePurposeTag(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_get_Width(This,value) \
    ( (This)->lpVtbl->get_Width(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_get_Height(This,value) \
    ( (This)->lpVtbl->get_Height(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreImage_get_Caption(This,value) \
    ( (This)->lpVtbl->get_Caption(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreImage;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreImage_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreLicense
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreLicense_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreLicense_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreLicense[] = L"Windows.Services.Store.IStoreLicense";
/* [object, uuid("26DC9579-4C4F-4F30-BC89-649F60E36055"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreLicenseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SkuStoreId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsActive )(
        __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExpirationDate )(
        __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InAppOfferToken )(
        __x_ABI_CWindows_CServices_CStore_CIStoreLicense * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreLicenseVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreLicense
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_get_SkuStoreId(This,value) \
    ( (This)->lpVtbl->get_SkuStoreId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_get_IsActive(This,value) \
    ( (This)->lpVtbl->get_IsActive(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_get_ExpirationDate(This,value) \
    ( (This)->lpVtbl->get_ExpirationDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreLicense_get_InAppOfferToken(This,value) \
    ( (This)->lpVtbl->get_InAppOfferToken(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreLicense;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreLicense_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageInstallOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageInstallOptions
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageInstallOptions[] = L"Windows.Services.Store.IStorePackageInstallOptions";
/* [object, uuid("1D3D630C-0CCD-44DD-8C59-80810A729973"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptionsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AllowForcedAppRestart )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AllowForcedAppRestart )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptionsVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptionsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_get_AllowForcedAppRestart(This,value) \
    ( (This)->lpVtbl->get_AllowForcedAppRestart(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_put_AllowForcedAppRestart(This,value) \
    ( (This)->lpVtbl->put_AllowForcedAppRestart(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageInstallOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStorePackageLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageLicense
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Foundation.IClosable
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageLicense[] = L"Windows.Services.Store.IStorePackageLicense";
/* [object, uuid("0C465714-14E1-4973-BD14-F77724271E99"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePackageLicenseVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LicenseLost )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStorePackageLicense_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LicenseLost )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Package )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CIPackage * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsValid )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *ReleaseLicense )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePackageLicenseVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePackageLicenseVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_add_LicenseLost(This,handler,token) \
    ( (This)->lpVtbl->add_LicenseLost(This,handler,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_remove_LicenseLost(This,token) \
    ( (This)->lpVtbl->remove_LicenseLost(This,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_get_Package(This,value) \
    ( (This)->lpVtbl->get_Package(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_get_IsValid(This,value) \
    ( (This)->lpVtbl->get_IsValid(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_ReleaseLicense(This) \
    ( (This)->lpVtbl->ReleaseLicense(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageLicense;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageLicense_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageUpdate
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageUpdate
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageUpdate[] = L"Windows.Services.Store.IStorePackageUpdate";
/* [object, uuid("140FA150-3CBF-4A35-B91F-48271C31B072"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Package )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CIPackage * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Mandatory )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_get_Package(This,value) \
    ( (This)->lpVtbl->get_Package(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_get_Mandatory(This,value) \
    ( (This)->lpVtbl->get_Mandatory(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdate_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageUpdateResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageUpdateResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageUpdateResult[] = L"Windows.Services.Store.IStorePackageUpdateResult";
/* [object, uuid("E79142ED-61F9-4893-B4FE-CF191603AF7B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OverallState )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StorePackageUpdateStatuses )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStorePackageUpdateStatus * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_get_OverallState(This,value) \
    ( (This)->lpVtbl->get_OverallState(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_get_StorePackageUpdateStatuses(This,value) \
    ( (This)->lpVtbl->get_StorePackageUpdateStatuses(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePackageUpdateResult2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePackageUpdateResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePackageUpdateResult2[] = L"Windows.Services.Store.IStorePackageUpdateResult2";
/* [object, uuid("071D012E-BC62-4F2E-87EA-99D801AEAF98"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StoreQueueItems )(
        __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2 * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreQueueItem * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_get_StoreQueueItems(This,value) \
    ( (This)->lpVtbl->get_StoreQueueItems(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePackageUpdateResult2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStorePrice
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePrice
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePrice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePrice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePrice[] = L"Windows.Services.Store.IStorePrice";
/* [object, uuid("55BA94C4-15F1-407C-8F06-006380F4DF0B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePriceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePrice * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePrice * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_FormattedBasePrice )(
        __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_FormattedPrice )(
        __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsOnSale )(
        __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SaleEndDate )(
        __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CurrencyCode )(
        __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_FormattedRecurrencePrice )(
        __x_ABI_CWindows_CServices_CStore_CIStorePrice * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePriceVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePrice
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePriceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_get_FormattedBasePrice(This,value) \
    ( (This)->lpVtbl->get_FormattedBasePrice(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_get_FormattedPrice(This,value) \
    ( (This)->lpVtbl->get_FormattedPrice(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_get_IsOnSale(This,value) \
    ( (This)->lpVtbl->get_IsOnSale(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_get_SaleEndDate(This,value) \
    ( (This)->lpVtbl->get_SaleEndDate(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_get_CurrencyCode(This,value) \
    ( (This)->lpVtbl->get_CurrencyCode(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePrice_get_FormattedRecurrencePrice(This,value) \
    ( (This)->lpVtbl->get_FormattedRecurrencePrice(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePrice;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePrice_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProduct
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProduct
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProduct_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProduct_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProduct[] = L"Windows.Services.Store.IStoreProduct";
/* [object, uuid("320E2C52-D760-450A-A42B-67D1E901AC90"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreProductVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StoreId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Language )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Title )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Description )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ProductKind )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HasDigitalDownload )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Keywords )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Images )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreImage * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Videos )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Skus )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreSku * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInUserCollection )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Price )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStorePrice * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LinkUri )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetIsAnySkuInstalledAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseWithPurchasePropertiesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * storePurchaseProperties,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InAppOfferToken )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProduct * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreProductVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreProduct
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreProductVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_StoreId(This,value) \
    ( (This)->lpVtbl->get_StoreId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Language(This,value) \
    ( (This)->lpVtbl->get_Language(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Title(This,value) \
    ( (This)->lpVtbl->get_Title(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Description(This,value) \
    ( (This)->lpVtbl->get_Description(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_ProductKind(This,value) \
    ( (This)->lpVtbl->get_ProductKind(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_HasDigitalDownload(This,value) \
    ( (This)->lpVtbl->get_HasDigitalDownload(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Keywords(This,value) \
    ( (This)->lpVtbl->get_Keywords(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Images(This,value) \
    ( (This)->lpVtbl->get_Images(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Videos(This,value) \
    ( (This)->lpVtbl->get_Videos(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Skus(This,value) \
    ( (This)->lpVtbl->get_Skus(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_IsInUserCollection(This,value) \
    ( (This)->lpVtbl->get_IsInUserCollection(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_Price(This,value) \
    ( (This)->lpVtbl->get_Price(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_LinkUri(This,value) \
    ( (This)->lpVtbl->get_LinkUri(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_GetIsAnySkuInstalledAsync(This,operation) \
    ( (This)->lpVtbl->GetIsAnySkuInstalledAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_RequestPurchaseAsync(This,operation) \
    ( (This)->lpVtbl->RequestPurchaseAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_RequestPurchaseWithPurchasePropertiesAsync(This,storePurchaseProperties,operation) \
    ( (This)->lpVtbl->RequestPurchaseWithPurchasePropertiesAsync(This,storePurchaseProperties,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProduct_get_InAppOfferToken(This,value) \
    ( (This)->lpVtbl->get_InAppOfferToken(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProduct;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProduct_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProductOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductOptions
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductOptions[] = L"Windows.Services.Store.IStoreProductOptions";
/* [object, uuid("5B34A0F9-A113-4811-8326-16199C927F31"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreProductOptionsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ActionFilters )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_HSTRING * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreProductOptionsVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreProductOptionsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_get_ActionFilters(This,value) \
    ( (This)->lpVtbl->get_ActionFilters(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductOptions;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreProductPagedQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductPagedQueryResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductPagedQueryResult[] = L"Windows.Services.Store.IStoreProductPagedQueryResult";
/* [object, uuid("C92718C5-4DD5-4869-A462-ECC6872E43C5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Products )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HasMoreResults )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetNextAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreProductPagedQueryResult * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_get_Products(This,value) \
    ( (This)->lpVtbl->get_Products(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_get_HasMoreResults(This,value) \
    ( (This)->lpVtbl->get_HasMoreResults(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_GetNextAsync(This,operation) \
    ( (This)->lpVtbl->GetNextAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductPagedQueryResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProductQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductQueryResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductQueryResult[] = L"Windows.Services.Store.IStoreProductQueryResult";
/* [object, uuid("D805E6C5-D456-4FF6-8049-9076D5165F73"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Products )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This,
        /* [retval, out] */__RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CServices__CStore__CStoreProduct * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_get_Products(This,value) \
    ( (This)->lpVtbl->get_Products(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductQueryResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreProductResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreProductResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreProductResult[] = L"Windows.Services.Store.IStoreProductResult";
/* [object, uuid("B7674F73-3C87-4EE1-8201-F428359BD3AF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreProductResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Product )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreProduct * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreProductResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreProductResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreProductResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreProductResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_get_Product(This,value) \
    ( (This)->lpVtbl->get_Product(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreProductResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreProductResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreProductResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePurchaseProperties
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePurchaseProperties
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePurchaseProperties[] = L"Windows.Services.Store.IStorePurchaseProperties";
/* [object, uuid("836278F3-FF87-4364-A5B4-FD2153EBE43B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Name )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Name )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * This,
        /* [in] */__RPC__in HSTRING value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_get_Name(This,value) \
    ( (This)->lpVtbl->get_Name(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_put_Name(This,value) \
    ( (This)->lpVtbl->put_Name(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_put_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->put_ExtendedJsonData(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePurchasePropertiesFactory
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePurchaseProperties
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePurchasePropertiesFactory[] = L"Windows.Services.Store.IStorePurchasePropertiesFactory";
/* [object, uuid("A768F59E-FEFD-489F-9A17-22A593E68B9D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory * This,
        /* [in] */__RPC__in HSTRING name,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * * storePurchaseProperties
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactoryVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_Create(This,name,storePurchaseProperties) \
    ( (This)->lpVtbl->Create(This,name,storePurchaseProperties) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchasePropertiesFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStorePurchaseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StorePurchaseResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStorePurchaseResult[] = L"Windows.Services.Store.IStorePurchaseResult";
/* [object, uuid("ADD28552-F96A-463D-A7BB-C20B4FCA6952"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStorePurchaseStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStorePurchaseResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItem
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItem
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItem[] = L"Windows.Services.Store.IStoreQueueItem";
/* [object, uuid("56D5C32B-F830-4293-9188-CAD2DCDE7357"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ProductId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PackageFamilyName )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InstallKind )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreQueueItemKind * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetCurrentStatus )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * * result
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Completed )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_Windows__CServices__CStore__CStoreQueueItemCompletedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Completed )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_StatusChanged )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CServices__CStore__CStoreQueueItem_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_StatusChanged )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_get_ProductId(This,value) \
    ( (This)->lpVtbl->get_ProductId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_get_PackageFamilyName(This,value) \
    ( (This)->lpVtbl->get_PackageFamilyName(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_get_InstallKind(This,value) \
    ( (This)->lpVtbl->get_InstallKind(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_GetCurrentStatus(This,result) \
    ( (This)->lpVtbl->GetCurrentStatus(This,result) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_add_Completed(This,handler,token) \
    ( (This)->lpVtbl->add_Completed(This,handler,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_remove_Completed(This,token) \
    ( (This)->lpVtbl->remove_Completed(This,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_add_StatusChanged(This,handler,token) \
    ( (This)->lpVtbl->add_StatusChanged(This,handler,token) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_remove_StatusChanged(This,token) \
    ( (This)->lpVtbl->remove_StatusChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItem;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItem2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItem
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItem2[] = L"Windows.Services.Store.IStoreQueueItem2";
/* [object, uuid("69491CA8-1AD4-447C-AD8C-A95035F64D82"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CancelInstallAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * action
        );
    HRESULT ( STDMETHODCALLTYPE *PauseInstallAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * action
        );
    HRESULT ( STDMETHODCALLTYPE *ResumeInstallAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * action
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_CancelInstallAsync(This,action) \
    ( (This)->lpVtbl->CancelInstallAsync(This,action) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_PauseInstallAsync(This,action) \
    ( (This)->lpVtbl->PauseInstallAsync(This,action) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_ResumeInstallAsync(This,action) \
    ( (This)->lpVtbl->ResumeInstallAsync(This,action) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItem2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItemCompletedEventArgs
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItemCompletedEventArgs
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItemCompletedEventArgs[] = L"Windows.Services.Store.IStoreQueueItemCompletedEventArgs";
/* [object, uuid("1247DF6C-B44A-439B-BB07-1D3003D005C2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgsVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemCompletedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreQueueItemStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreQueueItemStatus
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreQueueItemStatus[] = L"Windows.Services.Store.IStoreQueueItemStatus";
/* [object, uuid("9BD6796F-9CC3-4EC3-B2EF-7BE433B30174"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PackageInstallState )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreQueueItemState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PackageInstallExtendedState )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreQueueItemExtendedState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UpdateStatus )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStorePackageUpdateStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatusVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_get_PackageInstallState(This,value) \
    ( (This)->lpVtbl->get_PackageInstallState(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_get_PackageInstallExtendedState(This,value) \
    ( (This)->lpVtbl->get_PackageInstallExtendedState(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_get_UpdateStatus(This,value) \
    ( (This)->lpVtbl->get_UpdateStatus(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreQueueItemStatus_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreRateAndReviewResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreRateAndReviewResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreRateAndReviewResult[] = L"Windows.Services.Store.IStoreRateAndReviewResult";
/* [object, uuid("9D209D56-A6B5-4121-9B61-EE6D0FBDBDBB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WasUpdated )(
        __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreRateAndReviewStatus * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_get_WasUpdated(This,value) \
    ( (This)->lpVtbl->get_WasUpdated(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRateAndReviewResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Services.Store.IStoreRequestHelperStatics
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreRequestHelper
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreRequestHelperStatics[] = L"Windows.Services.Store.IStoreRequestHelperStatics";
/* [object, uuid("6CE5E5F9-A0C9-4B2C-96A6-A171C630038D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *SendRequestAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStoreContext * context,
        /* [in] */UINT32 requestKind,
        /* [in] */__RPC__in HSTRING parametersAsJson,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStoreSendRequestResult * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStaticsVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_SendRequestAsync(This,context,requestKind,parametersAsJson,operation) \
    ( (This)->lpVtbl->SendRequestAsync(This,context,requestKind,parametersAsJson,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreRequestHelperStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreSendRequestResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSendRequestResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSendRequestResult[] = L"Windows.Services.Store.IStoreSendRequestResult";
/* [object, uuid("C73ABE60-8272-4502-8A69-6E75153A4299"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Response )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_get_Response(This,value) \
    ( (This)->lpVtbl->get_Response(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreSendRequestResult2
 *
 * Introduced to Windows.Services.Store.StoreContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSendRequestResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSendRequestResult2[] = L"Windows.Services.Store.IStoreSendRequestResult2";
/* [object, uuid("2901296F-C0B0-49D0-8E8D-AA940AF9C10B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HttpStatusCode )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2 * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CHttp_CHttpStatusCode * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2Vtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_get_HttpStatusCode(This,value) \
    ( (This)->lpVtbl->get_HttpStatusCode(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSendRequestResult2_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.Services.Store.IStoreSku
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSku
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSku_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSku_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSku[] = L"Windows.Services.Store.IStoreSku";
/* [object, uuid("397E6F55-4440-4F03-863C-91F3FEC83D79"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreSkuVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSku * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSku * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StoreId )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Language )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Title )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Description )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsTrial )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CustomDeveloperData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Images )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreImage * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Videos )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreVideo * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Availabilities )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CServices__CStore__CStoreAvailability * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Price )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStorePrice * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedJsonData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInUserCollection )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BundledSkus )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CollectionData )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreCollectionData * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetIsInstalledAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPurchaseWithPurchasePropertiesAsync )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CServices_CStore_CIStorePurchaseProperties * storePurchaseProperties,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CServices__CStore__CStorePurchaseResult * * operation
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsSubscription )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SubscriptionInfo )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSku * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreSkuVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreSku
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreSkuVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_StoreId(This,value) \
    ( (This)->lpVtbl->get_StoreId(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Language(This,value) \
    ( (This)->lpVtbl->get_Language(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Title(This,value) \
    ( (This)->lpVtbl->get_Title(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Description(This,value) \
    ( (This)->lpVtbl->get_Description(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_IsTrial(This,value) \
    ( (This)->lpVtbl->get_IsTrial(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_CustomDeveloperData(This,value) \
    ( (This)->lpVtbl->get_CustomDeveloperData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Images(This,value) \
    ( (This)->lpVtbl->get_Images(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Videos(This,value) \
    ( (This)->lpVtbl->get_Videos(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Availabilities(This,value) \
    ( (This)->lpVtbl->get_Availabilities(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_Price(This,value) \
    ( (This)->lpVtbl->get_Price(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_ExtendedJsonData(This,value) \
    ( (This)->lpVtbl->get_ExtendedJsonData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_IsInUserCollection(This,value) \
    ( (This)->lpVtbl->get_IsInUserCollection(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_BundledSkus(This,value) \
    ( (This)->lpVtbl->get_BundledSkus(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_CollectionData(This,value) \
    ( (This)->lpVtbl->get_CollectionData(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_GetIsInstalledAsync(This,operation) \
    ( (This)->lpVtbl->GetIsInstalledAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_RequestPurchaseAsync(This,operation) \
    ( (This)->lpVtbl->RequestPurchaseAsync(This,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_RequestPurchaseWithPurchasePropertiesAsync(This,storePurchaseProperties,operation) \
    ( (This)->lpVtbl->RequestPurchaseWithPurchasePropertiesAsync(This,storePurchaseProperties,operation) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_IsSubscription(This,value) \
    ( (This)->lpVtbl->get_IsSubscription(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSku_get_SubscriptionInfo(This,value) \
    ( (This)->lpVtbl->get_SubscriptionInfo(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSku;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSku_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreSubscriptionInfo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreSubscriptionInfo
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreSubscriptionInfo[] = L"Windows.Services.Store.IStoreSubscriptionInfo";
/* [object, uuid("4189776A-0559-43AC-A9C6-3AB0011FB8EB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BillingPeriod )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BillingPeriodUnit )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreDurationUnit * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HasTrialPeriod )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrialPeriod )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrialPeriodUnit )(
        __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreDurationUnit * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfoVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_get_BillingPeriod(This,value) \
    ( (This)->lpVtbl->get_BillingPeriod(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_get_BillingPeriodUnit(This,value) \
    ( (This)->lpVtbl->get_BillingPeriodUnit(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_get_HasTrialPeriod(This,value) \
    ( (This)->lpVtbl->get_HasTrialPeriod(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_get_TrialPeriod(This,value) \
    ( (This)->lpVtbl->get_TrialPeriod(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_get_TrialPeriodUnit(This,value) \
    ( (This)->lpVtbl->get_TrialPeriodUnit(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreSubscriptionInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Services.Store.IStoreUninstallStorePackageResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreUninstallStorePackageResult
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreUninstallStorePackageResult[] = L"Windows.Services.Store.IStoreUninstallStorePackageResult";
/* [object, uuid("9FCA39FD-126F-4CDA-B801-1346B8D0A260"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CServices_CStore_CStoreUninstallStorePackageStatus * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResultVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreUninstallStorePackageResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Services.Store.IStoreVideo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Services.Store.StoreVideo
 *
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CServices_CStore_CIStoreVideo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CServices_CStore_CIStoreVideo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Services_Store_IStoreVideo[] = L"Windows.Services.Store.IStoreVideo";
/* [object, uuid("F26CB184-6F5E-4DC2-886C-3C63083C2F94"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CServices_CStore_CIStoreVideoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_VideoPurposeTag )(
        __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Width )(
        __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Height )(
        __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Caption )(
        __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PreviewImage )(
        __x_ABI_CWindows_CServices_CStore_CIStoreVideo * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CServices_CStore_CIStoreImage * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CServices_CStore_CIStoreVideoVtbl;

interface __x_ABI_CWindows_CServices_CStore_CIStoreVideo
{
    CONST_VTBL struct __x_ABI_CWindows_CServices_CStore_CIStoreVideoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_get_VideoPurposeTag(This,value) \
    ( (This)->lpVtbl->get_VideoPurposeTag(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_get_Width(This,value) \
    ( (This)->lpVtbl->get_Width(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_get_Height(This,value) \
    ( (This)->lpVtbl->get_Height(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_get_Caption(This,value) \
    ( (This)->lpVtbl->get_Caption(This,value) )

#define __x_ABI_CWindows_CServices_CStore_CIStoreVideo_get_PreviewImage(This,value) \
    ( (This)->lpVtbl->get_PreviewImage(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CServices_CStore_CIStoreVideo;
#endif /* !defined(____x_ABI_CWindows_CServices_CStore_CIStoreVideo_INTERFACE_DEFINED__) */
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreAcquireLicenseResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreAcquireLicenseResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreAcquireLicenseResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreAcquireLicenseResult[] = L"Windows.Services.Store.StoreAcquireLicenseResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreAppLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreAppLicense ** Default Interface **
 *    Windows.Services.Store.IStoreAppLicense2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreAppLicense_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreAppLicense_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreAppLicense[] = L"Windows.Services.Store.StoreAppLicense";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreAvailability
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreAvailability ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreAvailability_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreAvailability_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreAvailability[] = L"Windows.Services.Store.StoreAvailability";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreCanAcquireLicenseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreCanAcquireLicenseResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreCanAcquireLicenseResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreCanAcquireLicenseResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreCanAcquireLicenseResult[] = L"Windows.Services.Store.StoreCanAcquireLicenseResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreCollectionData
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreCollectionData ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreCollectionData_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreCollectionData_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreCollectionData[] = L"Windows.Services.Store.StoreCollectionData";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreConsumableResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreConsumableResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreConsumableResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreConsumableResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreConsumableResult[] = L"Windows.Services.Store.StoreConsumableResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreContext
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Services.Store.IStoreContextStatics interface starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreContext ** Default Interface **
 *    Windows.Services.Store.IStoreContext2
 *    Windows.Services.Store.IStoreContext3
 *    Windows.Services.Store.IStoreContext4
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreContext_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreContext_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreContext[] = L"Windows.Services.Store.StoreContext";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreImage
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreImage ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreImage_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreImage_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreImage[] = L"Windows.Services.Store.StoreImage";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreLicense ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreLicense_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreLicense_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreLicense[] = L"Windows.Services.Store.StoreLicense";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePackageInstallOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 3.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageInstallOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageInstallOptions_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageInstallOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageInstallOptions[] = L"Windows.Services.Store.StorePackageInstallOptions";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StorePackageLicense
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageLicense ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageLicense_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageLicense_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageLicense[] = L"Windows.Services.Store.StorePackageLicense";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePackageUpdate
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageUpdate ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageUpdate_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageUpdate_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageUpdate[] = L"Windows.Services.Store.StorePackageUpdate";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePackageUpdateResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePackageUpdateResult ** Default Interface **
 *    Windows.Services.Store.IStorePackageUpdateResult2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePackageUpdateResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePackageUpdateResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePackageUpdateResult[] = L"Windows.Services.Store.StorePackageUpdateResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePrice
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePrice ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePrice_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePrice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePrice[] = L"Windows.Services.Store.StorePrice";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProduct
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProduct ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProduct_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProduct_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProduct[] = L"Windows.Services.Store.StoreProduct";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProductOptions
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 3.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductOptions ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductOptions_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductOptions[] = L"Windows.Services.Store.StoreProductOptions";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreProductPagedQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductPagedQueryResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductPagedQueryResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductPagedQueryResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductPagedQueryResult[] = L"Windows.Services.Store.StoreProductPagedQueryResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProductQueryResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductQueryResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductQueryResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductQueryResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductQueryResult[] = L"Windows.Services.Store.StoreProductQueryResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreProductResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreProductResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreProductResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreProductResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreProductResult[] = L"Windows.Services.Store.StoreProductResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePurchaseProperties
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *   Type can be activated via the Windows.Services.Store.IStorePurchasePropertiesFactory interface starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePurchaseProperties ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePurchaseProperties_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePurchaseProperties_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePurchaseProperties[] = L"Windows.Services.Store.StorePurchaseProperties";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StorePurchaseResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStorePurchaseResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StorePurchaseResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StorePurchaseResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StorePurchaseResult[] = L"Windows.Services.Store.StorePurchaseResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreQueueItem
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreQueueItem ** Default Interface **
 *    Windows.Services.Store.IStoreQueueItem2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreQueueItem_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreQueueItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreQueueItem[] = L"Windows.Services.Store.StoreQueueItem";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreQueueItemCompletedEventArgs
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreQueueItemCompletedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreQueueItemCompletedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreQueueItemCompletedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreQueueItemCompletedEventArgs[] = L"Windows.Services.Store.StoreQueueItemCompletedEventArgs";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreQueueItemStatus
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreQueueItemStatus ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreQueueItemStatus_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreQueueItemStatus_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreQueueItemStatus[] = L"Windows.Services.Store.StoreQueueItemStatus";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreRateAndReviewResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 4.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreRateAndReviewResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreRateAndReviewResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreRateAndReviewResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreRateAndReviewResult[] = L"Windows.Services.Store.StoreRateAndReviewResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.Services.Store.StoreRequestHelper
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Services.Store.IStoreRequestHelperStatics interface starting with version 1.0 of the Windows.Services.Store.StoreContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_Services_Store_StoreRequestHelper_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreRequestHelper_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreRequestHelper[] = L"Windows.Services.Store.StoreRequestHelper";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreSendRequestResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreSendRequestResult ** Default Interface **
 *    Windows.Services.Store.IStoreSendRequestResult2
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreSendRequestResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreSendRequestResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreSendRequestResult[] = L"Windows.Services.Store.StoreSendRequestResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreSku
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreSku ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreSku_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreSku_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreSku[] = L"Windows.Services.Store.StoreSku";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreSubscriptionInfo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreSubscriptionInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreSubscriptionInfo_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreSubscriptionInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreSubscriptionInfo[] = L"Windows.Services.Store.StoreSubscriptionInfo";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Services.Store.StoreUninstallStorePackageResult
 *
 * Introduced to Windows.Services.Store.StoreContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreUninstallStorePackageResult ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreUninstallStorePackageResult_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreUninstallStorePackageResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreUninstallStorePackageResult[] = L"Windows.Services.Store.StoreUninstallStorePackageResult";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.Services.Store.StoreVideo
 *
 * Introduced to Windows.Services.Store.StoreContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Services.Store.IStoreVideo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Services_Store_StoreVideo_DEFINED
#define RUNTIMECLASS_Windows_Services_Store_StoreVideo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Services_Store_StoreVideo[] = L"Windows.Services.Store.StoreVideo";
#endif
#endif // WINDOWS_SERVICES_STORE_STORECONTRACT_VERSION >= 0x10000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eservices2Estore_p_h__

#endif // __windows2Eservices2Estore_h__
