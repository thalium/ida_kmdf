/* Header file automatically generated from windows.web.ui.idl */
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
#ifndef __windows2Eweb2Eui_h__
#define __windows2Eweb2Eui_h__
#ifndef __windows2Eweb2Eui_p_h__
#define __windows2Eweb2Eui_p_h__


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
#include "Windows.ApplicationModel.DataTransfer.h"
#include "Windows.Storage.Streams.h"
#include "Windows.UI.h"
#include "Windows.Web.h"
#include "Windows.Web.Http.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControl;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl ABI::Windows::Web::UI::IWebViewControl

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControl2;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 ABI::Windows::Web::UI::IWebViewControl2

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlContentLoadingEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs ABI::Windows::Web::UI::IWebViewControlContentLoadingEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlDOMContentLoadedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs ABI::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlDeferredPermissionRequest;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlLongRunningScriptDetectedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs ABI::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlNavigationCompletedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs ABI::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlNavigationStartingEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs ABI::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlNewWindowRequestedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs ABI::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlNewWindowRequestedEventArgs2;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 ABI::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlPermissionRequest;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest ABI::Windows::Web::UI::IWebViewControlPermissionRequest

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlPermissionRequestedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs ABI::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlScriptNotifyEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs ABI::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlSettings;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings ABI::Windows::Web::UI::IWebViewControlSettings

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs ABI::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlUnviewableContentIdentifiedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs ABI::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                interface IWebViewControlWebResourceRequestedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs ABI::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlDeferredPermissionRequest;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE
#define DEF___FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("277a80bd-3e2a-5fe8-95d2-cc86f723bf42"))
IIterator<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*, ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Web.UI.WebViewControlDeferredPermissionRequest>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*> __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t;
#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>
//#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE
#define DEF___FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("91805f3f-13cb-5483-b592-b9ae0e334f17"))
IIterable<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*, ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Web.UI.WebViewControlDeferredPermissionRequest>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*> __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t;
#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>
//#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE
#define DEF___FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("bffd3dcf-1974-53a2-8d88-966d84ba98e0"))
IVectorView<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*, ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Web.UI.WebViewControlDeferredPermissionRequest>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Web::UI::WebViewControlDeferredPermissionRequest*> __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t;
#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>
//#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b5089479-abd8-5985-8a93-4c208a85e3a4"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlContentLoadingEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("357154fe-ec1a-5fca-b860-62f03dece49d"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlContentLoadingEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlContentLoadingEventArgs*, ABI::Windows::Web::UI::IWebViewControlContentLoadingEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlContentLoadingEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlContentLoadingEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlContentLoadingEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlContentLoadingEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlDOMContentLoadedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d7dc333e-b521-5b76-a7ff-48b454f597e5"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs*, ABI::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlLongRunningScriptDetectedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("bd29249e-4112-533d-96a2-0a1c01519caf"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs*, ABI::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlNavigationCompletedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("57a87c53-47a5-5864-9881-fd4c00f230a9"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs*, ABI::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlNavigationCompletedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlNavigationStartingEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e92e0bcc-9ae9-5b9b-a684-83dd8ee57775"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlNavigationStartingEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlNavigationStartingEventArgs*, ABI::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlNavigationStartingEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlNavigationStartingEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlNewWindowRequestedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("317111df-10c6-559c-85a1-847eb0a1b2d5"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs*, ABI::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlPermissionRequestedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e5cacc26-2a68-5e0a-b82b-b3d756e10a56"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs*, ABI::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlPermissionRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlScriptNotifyEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ee8b81d3-bbc2-55b0-877b-6ba86e3ad899"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlScriptNotifyEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlScriptNotifyEventArgs*, ABI::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlScriptNotifyEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlScriptNotifyEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlUnsupportedUriSchemeIdentifiedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("8658050c-5e47-5516-b25b-57fae22c4b88"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs*, ABI::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlUnviewableContentIdentifiedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("571626e3-9780-5b37-be8a-ab8e4e7898cf"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs*, ABI::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlWebResourceRequestedEventArgs;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3a6ed2bc-032b-5ec7-a20a-c1ef49250c3c"))
ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs*, ABI::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.IWebViewControl, Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


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



namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace DataTransfer {
                class DataPackage;
            } /* DataTransfer */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace DataTransfer {
                interface IDataPackage;
            } /* DataTransfer */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage ABI::Windows::ApplicationModel::DataTransfer::IDataPackage

#endif // ____x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("a93a3b99-e946-57ce-aad9-c23d138c353e"))
IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::DataTransfer::DataPackage*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::DataTransfer::DataPackage*, ABI::Windows::ApplicationModel::DataTransfer::IDataPackage*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.ApplicationModel.DataTransfer.DataPackage>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::DataTransfer::DataPackage*> __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::DataTransfer::IDataPackage*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::ApplicationModel::DataTransfer::IDataPackage*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_USE
#define DEF___FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("a16f2d07-ead3-53e4-9490-75bdbaeb7a5b"))
IAsyncOperation<ABI::Windows::ApplicationModel::DataTransfer::DataPackage*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::ApplicationModel::DataTransfer::DataPackage*, ABI::Windows::ApplicationModel::DataTransfer::IDataPackage*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.ApplicationModel.DataTransfer.DataPackage>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::ApplicationModel::DataTransfer::DataPackage*> __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_t;
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::DataTransfer::IDataPackage*>
//#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::ApplicationModel::DataTransfer::IDataPackage*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_USE */


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




#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            namespace Streams {
                interface IRandomAccessStream;
            } /* Streams */
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream ABI::Windows::Storage::Streams::IRandomAccessStream

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace UI {
            
            typedef struct Color Color;
            
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Web {
            namespace Http {
                class HttpRequestMessage;
            } /* Http */
        } /* Web */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace Http {
                interface IHttpRequestMessage;
            } /* Http */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage ABI::Windows::Web::Http::IHttpRequestMessage

#endif // ____x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace Http {
                class HttpResponseMessage;
            } /* Http */
        } /* Web */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace Http {
                interface IHttpResponseMessage;
            } /* Http */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage ABI::Windows::Web::Http::IHttpResponseMessage

#endif // ____x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CWeb_CIUriToStreamResolver_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CIUriToStreamResolver_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            interface IUriToStreamResolver;
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CIUriToStreamResolver ABI::Windows::Web::IUriToStreamResolver

#endif // ____x_ABI_CWindows_CWeb_CIUriToStreamResolver_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace Web {
            
            typedef enum WebErrorStatus : int WebErrorStatus;
            
        } /* Web */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                
                typedef enum WebViewControlPermissionState : int WebViewControlPermissionState;
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                
                typedef enum WebViewControlPermissionType : int WebViewControlPermissionType;
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

























namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlPermissionRequest;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                class WebViewControlSettings;
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */













/*
 *
 * Struct Windows.Web.UI.WebViewControlPermissionState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [v1_enum, contract] */
                enum WebViewControlPermissionState : int
                {
                    WebViewControlPermissionState_Unknown = 0,
                    WebViewControlPermissionState_Defer = 1,
                    WebViewControlPermissionState_Allow = 2,
                    WebViewControlPermissionState_Deny = 3,
                };
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Web.UI.WebViewControlPermissionType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [v1_enum, contract] */
                enum WebViewControlPermissionType : int
                {
                    WebViewControlPermissionType_Geolocation = 0,
                    WebViewControlPermissionType_UnlimitedIndexedDBQuota = 1,
                    WebViewControlPermissionType_Media = 2,
                    WebViewControlPermissionType_PointerLock = 3,
                    WebViewControlPermissionType_WebNotifications = 4,
                    WebViewControlPermissionType_Screen = 5,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
                    
                    WebViewControlPermissionType_ImmersiveView = 6,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
                    
                };
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControl[] = L"Windows.Web.UI.IWebViewControl";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("3F921316-BC70-4BDA-9136-C94370899FAB"), contract] */
                MIDL_INTERFACE("3F921316-BC70-4BDA-9136-C94370899FAB")
                IWebViewControl : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Source(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Source(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * source
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DocumentTitle(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanGoBack(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanGoForward(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DefaultBackgroundColor(
                        /* [in] */ABI::Windows::UI::Color value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DefaultBackgroundColor(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContainsFullScreenElement(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Settings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::UI::IWebViewControlSettings * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeferredPermissionRequests(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GoForward(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GoBack(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Refresh(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Stop(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Navigate(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * source
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NavigateToString(
                        /* [in] */__RPC__in HSTRING text
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NavigateToLocalStreamUri(
                        /* [in] */__RPC__in_opt ABI::Windows::Foundation::IUriRuntimeClass * source,
                        /* [in] */__RPC__in_opt ABI::Windows::Web::IUriToStreamResolver * streamResolver
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE NavigateWithHttpRequestMessage(
                        /* [in] */__RPC__in_opt ABI::Windows::Web::Http::IHttpRequestMessage * requestMessage
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE InvokeScriptAsync(
                        /* [in] */__RPC__in HSTRING scriptName,
                        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * arguments,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CapturePreviewToStreamAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Storage::Streams::IRandomAccessStream * stream,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CaptureSelectedContentToDataPackageAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE BuildLocalStreamUri(
                        /* [in] */__RPC__in HSTRING contentIdentifier,
                        /* [in] */__RPC__in HSTRING relativePath,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDeferredPermissionRequestById(
                        /* [in] */UINT32 id,
                        /* [out] */__RPC__deref_out_opt ABI::Windows::Web::UI::IWebViewControlDeferredPermissionRequest * * result
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_NavigationStarting(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_NavigationStarting(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ContentLoading(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ContentLoading(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_DOMContentLoaded(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_DOMContentLoaded(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_NavigationCompleted(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_NavigationCompleted(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationStarting(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationStarting(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_FrameContentLoading(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_FrameContentLoading(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_FrameDOMContentLoaded(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_FrameDOMContentLoaded(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationCompleted(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationCompleted(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ScriptNotify(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ScriptNotify(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LongRunningScriptDetected(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LongRunningScriptDetected(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_UnsafeContentWarningDisplaying(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_UnsafeContentWarningDisplaying(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_UnviewableContentIdentified(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_UnviewableContentIdentified(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_PermissionRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_PermissionRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_UnsupportedUriSchemeIdentified(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_UnsupportedUriSchemeIdentified(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_NewWindowRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_NewWindowRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ContainsFullScreenElementChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ContainsFullScreenElementChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_WebResourceRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_WebResourceRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControl=_uuidof(IWebViewControl);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControl;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControl2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControl2[] = L"Windows.Web.UI.IWebViewControl2";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("4D3C06F9-C8DF-41CC-8BD5-2A947B204503"), contract] */
                MIDL_INTERFACE("4D3C06F9-C8DF-41CC-8BD5-2A947B204503")
                IWebViewControl2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE AddInitializeScript(
                        /* [in] */__RPC__in HSTRING script
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControl2=_uuidof(IWebViewControl2);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControl2;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlContentLoadingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlContentLoadingEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlContentLoadingEventArgs[] = L"Windows.Web.UI.IWebViewControlContentLoadingEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("9A3FCCB2-B9BB-404B-A22B-66DCCD1250C6"), exclusiveto, contract] */
                MIDL_INTERFACE("9A3FCCB2-B9BB-404B-A22B-66DCCD1250C6")
                IWebViewControlContentLoadingEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlContentLoadingEventArgs=_uuidof(IWebViewControlContentLoadingEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlDOMContentLoadedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlDOMContentLoadedEventArgs[] = L"Windows.Web.UI.IWebViewControlDOMContentLoadedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("BE8BC008-9541-4545-9FF2-2DF585B29F7D"), exclusiveto, contract] */
                MIDL_INTERFACE("BE8BC008-9541-4545-9FF2-2DF585B29F7D")
                IWebViewControlDOMContentLoadedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlDOMContentLoadedEventArgs=_uuidof(IWebViewControlDOMContentLoadedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlDeferredPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlDeferredPermissionRequest
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlDeferredPermissionRequest[] = L"Windows.Web.UI.IWebViewControlDeferredPermissionRequest";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("2CE349E0-D759-445C-9926-8995298F152B"), exclusiveto, contract] */
                MIDL_INTERFACE("2CE349E0-D759-445C-9926-8995298F152B")
                IWebViewControlDeferredPermissionRequest : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PermissionType(
                        /* [retval, out] */__RPC__out ABI::Windows::Web::UI::WebViewControlPermissionType * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Allow(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Deny(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlDeferredPermissionRequest=_uuidof(IWebViewControlDeferredPermissionRequest);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlLongRunningScriptDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs[] = L"Windows.Web.UI.IWebViewControlLongRunningScriptDetectedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("2A6E5BBA-98B4-45BC-BBEB-0F69CE49C599"), exclusiveto, contract] */
                MIDL_INTERFACE("2A6E5BBA-98B4-45BC-BBEB-0F69CE49C599")
                IWebViewControlLongRunningScriptDetectedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExecutionTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StopPageScriptExecution(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StopPageScriptExecution(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlLongRunningScriptDetectedEventArgs=_uuidof(IWebViewControlLongRunningScriptDetectedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNavigationCompletedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNavigationCompletedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs[] = L"Windows.Web.UI.IWebViewControlNavigationCompletedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("20409918-4A15-4C46-A55D-F79EDB0BDE8B"), exclusiveto, contract] */
                MIDL_INTERFACE("20409918-4A15-4C46-A55D-F79EDB0BDE8B")
                IWebViewControlNavigationCompletedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsSuccess(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WebErrorStatus(
                        /* [retval, out] */__RPC__out ABI::Windows::Web::WebErrorStatus * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlNavigationCompletedEventArgs=_uuidof(IWebViewControlNavigationCompletedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNavigationStartingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNavigationStartingEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs[] = L"Windows.Web.UI.IWebViewControlNavigationStartingEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("0C9057C5-0A08-41C7-863B-71E3A9549137"), exclusiveto, contract] */
                MIDL_INTERFACE("0C9057C5-0A08-41C7-863B-71E3A9549137")
                IWebViewControlNavigationStartingEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Cancel(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Cancel(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlNavigationStartingEventArgs=_uuidof(IWebViewControlNavigationStartingEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs[] = L"Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("3DF44BBB-A124-46D5-A083-D02CACDFF5AD"), exclusiveto, contract] */
                MIDL_INTERFACE("3DF44BBB-A124-46D5-A083-D02CACDFF5AD")
                IWebViewControlNewWindowRequestedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Referrer(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlNewWindowRequestedEventArgs=_uuidof(IWebViewControlNewWindowRequestedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2[] = L"Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs2";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("B53C5CA6-2AAE-4BFC-92B9-C30E92B48098"), exclusiveto, contract] */
                MIDL_INTERFACE("B53C5CA6-2AAE-4BFC-92B9-C30E92B48098")
                IWebViewControlNewWindowRequestedEventArgs2 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NewWindow(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::UI::IWebViewControl * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_NewWindow(
                        /* [in] */__RPC__in_opt ABI::Windows::Web::UI::IWebViewControl * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * deferral
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlNewWindowRequestedEventArgs2=_uuidof(IWebViewControlNewWindowRequestedEventArgs2);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlPermissionRequest
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlPermissionRequest[] = L"Windows.Web.UI.IWebViewControlPermissionRequest";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("E5BC836C-F22F-40E2-95B2-7729F840EB7F"), exclusiveto, contract] */
                MIDL_INTERFACE("E5BC836C-F22F-40E2-95B2-7729F840EB7F")
                IWebViewControlPermissionRequest : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PermissionType(
                        /* [retval, out] */__RPC__out ABI::Windows::Web::UI::WebViewControlPermissionType * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_State(
                        /* [retval, out] */__RPC__out ABI::Windows::Web::UI::WebViewControlPermissionState * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Defer(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Allow(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Deny(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlPermissionRequest=_uuidof(IWebViewControlPermissionRequest);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlPermissionRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlPermissionRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlPermissionRequestedEventArgs[] = L"Windows.Web.UI.IWebViewControlPermissionRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("27204D51-2488-4CC5-968E-0A771E59C147"), exclusiveto, contract] */
                MIDL_INTERFACE("27204D51-2488-4CC5-968E-0A771E59C147")
                IWebViewControlPermissionRequestedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PermissionRequest(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::UI::IWebViewControlPermissionRequest * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlPermissionRequestedEventArgs=_uuidof(IWebViewControlPermissionRequestedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlScriptNotifyEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlScriptNotifyEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlScriptNotifyEventArgs[] = L"Windows.Web.UI.IWebViewControlScriptNotifyEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("491DE57B-6F49-41BB-B591-51B85B817037"), exclusiveto, contract] */
                MIDL_INTERFACE("491DE57B-6F49-41BB-B591-51B85B817037")
                IWebViewControlScriptNotifyEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Value(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlScriptNotifyEventArgs=_uuidof(IWebViewControlScriptNotifyEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlSettings[] = L"Windows.Web.UI.IWebViewControlSettings";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("C9967FBF-5E98-4CFD-8CCE-27B0911E3DE8"), exclusiveto, contract] */
                MIDL_INTERFACE("C9967FBF-5E98-4CFD-8CCE-27B0911E3DE8")
                IWebViewControlSettings : public IInspectable
                {
                public:
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsJavaScriptEnabled(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsJavaScriptEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsIndexedDBEnabled(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsIndexedDBEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsScriptNotifyAllowed(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsScriptNotifyAllowed(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlSettings=_uuidof(IWebViewControlSettings);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs[] = L"Windows.Web.UI.IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("E3B81944-E4FC-43DC-94CA-F980F30BC51D"), exclusiveto, contract] */
                MIDL_INTERFACE("E3B81944-E4FC-43DC-94CA-F980F30BC51D")
                IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs=_uuidof(IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlUnviewableContentIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs[] = L"Windows.Web.UI.IWebViewControlUnviewableContentIdentifiedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("4A9680DB-88F2-4E20-B693-B4E2DF4AA581"), exclusiveto, contract] */
                MIDL_INTERFACE("4A9680DB-88F2-4E20-B693-B4E2DF4AA581")
                IWebViewControlUnviewableContentIdentifiedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Uri(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Referrer(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IUriRuntimeClass * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MediaType(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlUnviewableContentIdentifiedEventArgs=_uuidof(IWebViewControlUnviewableContentIdentifiedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlWebResourceRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs[] = L"Windows.Web.UI.IWebViewControlWebResourceRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                /* [object, uuid("44D6524D-55A4-4D8B-891C-931D8E25D42E"), exclusiveto, contract] */
                MIDL_INTERFACE("44D6524D-55A4-4D8B-891C-931D8E25D42E")
                IWebViewControlWebResourceRequestedEventArgs : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * deferral
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Request(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::Http::IHttpRequestMessage * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Response(
                        /* [in] */__RPC__in_opt ABI::Windows::Web::Http::IHttpResponseMessage * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Response(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::Http::IHttpResponseMessage * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWebViewControlWebResourceRequestedEventArgs=_uuidof(IWebViewControlWebResourceRequestedEventArgs);
                
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlContentLoadingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlContentLoadingEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlContentLoadingEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlContentLoadingEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlContentLoadingEventArgs[] = L"Windows.Web.UI.WebViewControlContentLoadingEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlDOMContentLoadedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlDOMContentLoadedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlDOMContentLoadedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlDOMContentLoadedEventArgs[] = L"Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlDeferredPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlDeferredPermissionRequest ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlDeferredPermissionRequest_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlDeferredPermissionRequest_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlDeferredPermissionRequest[] = L"Windows.Web.UI.WebViewControlDeferredPermissionRequest";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlLongRunningScriptDetectedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlLongRunningScriptDetectedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlLongRunningScriptDetectedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlLongRunningScriptDetectedEventArgs[] = L"Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlNavigationCompletedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlNavigationCompletedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationCompletedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationCompletedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlNavigationCompletedEventArgs[] = L"Windows.Web.UI.WebViewControlNavigationCompletedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlNavigationStartingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlNavigationStartingEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationStartingEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationStartingEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlNavigationStartingEventArgs[] = L"Windows.Web.UI.WebViewControlNavigationStartingEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs ** Default Interface **
 *    Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs2
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlNewWindowRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlNewWindowRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlNewWindowRequestedEventArgs[] = L"Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlPermissionRequest ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequest_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequest_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlPermissionRequest[] = L"Windows.Web.UI.WebViewControlPermissionRequest";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlPermissionRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlPermissionRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlPermissionRequestedEventArgs[] = L"Windows.Web.UI.WebViewControlPermissionRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlScriptNotifyEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlScriptNotifyEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlScriptNotifyEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlScriptNotifyEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlScriptNotifyEventArgs[] = L"Windows.Web.UI.WebViewControlScriptNotifyEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlSettings_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlSettings[] = L"Windows.Web.UI.WebViewControlSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlUnsupportedUriSchemeIdentifiedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlUnsupportedUriSchemeIdentifiedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlUnsupportedUriSchemeIdentifiedEventArgs[] = L"Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlUnviewableContentIdentifiedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlUnviewableContentIdentifiedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlUnviewableContentIdentifiedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlUnviewableContentIdentifiedEventArgs[] = L"Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlWebResourceRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlWebResourceRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlWebResourceRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlWebResourceRequestedEventArgs[] = L"Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControl __x_ABI_CWindows_CWeb_CUI_CIWebViewControl;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest;

typedef struct __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl;

interface __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest
{
    CONST_VTBL struct __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest;

typedef  struct __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest **first);

    END_INTERFACE
} __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl;

interface __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest
{
    CONST_VTBL struct __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest;

typedef struct __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
            /* [in] */ __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl;

interface __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest
{
    CONST_VTBL struct __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequestVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

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


#ifndef ____x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage __x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage;

#endif // ____x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackageVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackageVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackageVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage;

typedef struct __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackageVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CApplicationModel__CDataTransfer__CDataPackage **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CApplicationModel_CDataTransfer_CIDataPackage * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackageVtbl;

interface __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackageVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000






#ifndef ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIDeferral __x_ABI_CWindows_CFoundation_CIDeferral;

#endif // ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIAsyncAction __x_ABI_CWindows_CFoundation_CIAsyncAction;

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;


#ifndef ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIUriRuntimeClass __x_ABI_CWindows_CFoundation_CIUriRuntimeClass;

#endif // ____x_ABI_CWindows_CFoundation_CIUriRuntimeClass_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__






typedef struct __x_ABI_CWindows_CUI_CColor __x_ABI_CWindows_CUI_CColor;



#ifndef ____x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage __x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage;

#endif // ____x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage __x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage;

#endif // ____x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CWeb_CIUriToStreamResolver_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CIUriToStreamResolver_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CIUriToStreamResolver __x_ABI_CWindows_CWeb_CIUriToStreamResolver;

#endif // ____x_ABI_CWindows_CWeb_CIUriToStreamResolver_FWD_DEFINED__



typedef enum __x_ABI_CWindows_CWeb_CWebErrorStatus __x_ABI_CWindows_CWeb_CWebErrorStatus;




typedef enum __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionState __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionState;


typedef enum __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionType __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionType;








































/*
 *
 * Struct Windows.Web.UI.WebViewControlPermissionState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionState
{
    WebViewControlPermissionState_Unknown = 0,
    WebViewControlPermissionState_Defer = 1,
    WebViewControlPermissionState_Allow = 2,
    WebViewControlPermissionState_Deny = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Web.UI.WebViewControlPermissionType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionType
{
    WebViewControlPermissionType_Geolocation = 0,
    WebViewControlPermissionType_UnlimitedIndexedDBQuota = 1,
    WebViewControlPermissionType_Media = 2,
    WebViewControlPermissionType_PointerLock = 3,
    WebViewControlPermissionType_WebNotifications = 4,
    WebViewControlPermissionType_Screen = 5,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
    
    WebViewControlPermissionType_ImmersiveView = 6,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
    
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControl[] = L"Windows.Web.UI.IWebViewControl";
/* [object, uuid("3F921316-BC70-4BDA-9136-C94370899FAB"), contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Source )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Source )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * source
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DocumentTitle )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanGoBack )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanGoForward )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DefaultBackgroundColor )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DefaultBackgroundColor )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContainsFullScreenElement )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Settings )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeferredPermissionRequests )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CWeb__CUI__CWebViewControlDeferredPermissionRequest * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GoForward )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This
        );
    HRESULT ( STDMETHODCALLTYPE *GoBack )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This
        );
    HRESULT ( STDMETHODCALLTYPE *Refresh )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This
        );
    HRESULT ( STDMETHODCALLTYPE *Stop )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This
        );
    HRESULT ( STDMETHODCALLTYPE *Navigate )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * source
        );
    HRESULT ( STDMETHODCALLTYPE *NavigateToString )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in HSTRING text
        );
    HRESULT ( STDMETHODCALLTYPE *NavigateToLocalStreamUri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * source,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CWeb_CIUriToStreamResolver * streamResolver
        );
    HRESULT ( STDMETHODCALLTYPE *NavigateWithHttpRequestMessage )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage * requestMessage
        );
    HRESULT ( STDMETHODCALLTYPE *InvokeScriptAsync )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in HSTRING scriptName,
        /* [in] */__RPC__in_opt __FIIterable_1_HSTRING * arguments,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_HSTRING * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CapturePreviewToStreamAsync )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream * stream,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CaptureSelectedContentToDataPackageAsync )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CApplicationModel__CDataTransfer__CDataPackage * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *BuildLocalStreamUri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in HSTRING contentIdentifier,
        /* [in] */__RPC__in HSTRING relativePath,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferredPermissionRequestById )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */UINT32 id,
        /* [out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * * result
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_NavigationStarting )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_NavigationStarting )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ContentLoading )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ContentLoading )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_DOMContentLoaded )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_DOMContentLoaded )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_NavigationCompleted )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_NavigationCompleted )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_FrameNavigationStarting )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationStartingEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_FrameNavigationStarting )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_FrameContentLoading )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlContentLoadingEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_FrameContentLoading )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_FrameDOMContentLoaded )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlDOMContentLoadedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_FrameDOMContentLoaded )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_FrameNavigationCompleted )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNavigationCompletedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_FrameNavigationCompleted )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ScriptNotify )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlScriptNotifyEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ScriptNotify )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LongRunningScriptDetected )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlLongRunningScriptDetectedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LongRunningScriptDetected )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_UnsafeContentWarningDisplaying )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_UnsafeContentWarningDisplaying )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_UnviewableContentIdentified )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnviewableContentIdentifiedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_UnviewableContentIdentified )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_PermissionRequested )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlPermissionRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_PermissionRequested )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_UnsupportedUriSchemeIdentified )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_UnsupportedUriSchemeIdentified )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_NewWindowRequested )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlNewWindowRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_NewWindowRequested )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ContainsFullScreenElementChanged )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ContainsFullScreenElementChanged )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_WebResourceRequested )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CIWebViewControl_Windows__CWeb__CUI__CWebViewControlWebResourceRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_WebResourceRequested )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControl
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_Source(This,value) \
    ( (This)->lpVtbl->get_Source(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_put_Source(This,source) \
    ( (This)->lpVtbl->put_Source(This,source) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_DocumentTitle(This,value) \
    ( (This)->lpVtbl->get_DocumentTitle(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_CanGoBack(This,value) \
    ( (This)->lpVtbl->get_CanGoBack(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_CanGoForward(This,value) \
    ( (This)->lpVtbl->get_CanGoForward(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_put_DefaultBackgroundColor(This,value) \
    ( (This)->lpVtbl->put_DefaultBackgroundColor(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_DefaultBackgroundColor(This,value) \
    ( (This)->lpVtbl->get_DefaultBackgroundColor(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_ContainsFullScreenElement(This,value) \
    ( (This)->lpVtbl->get_ContainsFullScreenElement(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_Settings(This,value) \
    ( (This)->lpVtbl->get_Settings(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_get_DeferredPermissionRequests(This,value) \
    ( (This)->lpVtbl->get_DeferredPermissionRequests(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_GoForward(This) \
    ( (This)->lpVtbl->GoForward(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_GoBack(This) \
    ( (This)->lpVtbl->GoBack(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_Refresh(This) \
    ( (This)->lpVtbl->Refresh(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_Stop(This) \
    ( (This)->lpVtbl->Stop(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_Navigate(This,source) \
    ( (This)->lpVtbl->Navigate(This,source) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_NavigateToString(This,text) \
    ( (This)->lpVtbl->NavigateToString(This,text) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_NavigateToLocalStreamUri(This,source,streamResolver) \
    ( (This)->lpVtbl->NavigateToLocalStreamUri(This,source,streamResolver) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_NavigateWithHttpRequestMessage(This,requestMessage) \
    ( (This)->lpVtbl->NavigateWithHttpRequestMessage(This,requestMessage) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_InvokeScriptAsync(This,scriptName,arguments,operation) \
    ( (This)->lpVtbl->InvokeScriptAsync(This,scriptName,arguments,operation) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_CapturePreviewToStreamAsync(This,stream,operation) \
    ( (This)->lpVtbl->CapturePreviewToStreamAsync(This,stream,operation) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_CaptureSelectedContentToDataPackageAsync(This,operation) \
    ( (This)->lpVtbl->CaptureSelectedContentToDataPackageAsync(This,operation) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_BuildLocalStreamUri(This,contentIdentifier,relativePath,result) \
    ( (This)->lpVtbl->BuildLocalStreamUri(This,contentIdentifier,relativePath,result) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_GetDeferredPermissionRequestById(This,id,result) \
    ( (This)->lpVtbl->GetDeferredPermissionRequestById(This,id,result) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_NavigationStarting(This,handler,token) \
    ( (This)->lpVtbl->add_NavigationStarting(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_NavigationStarting(This,token) \
    ( (This)->lpVtbl->remove_NavigationStarting(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_ContentLoading(This,handler,token) \
    ( (This)->lpVtbl->add_ContentLoading(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_ContentLoading(This,token) \
    ( (This)->lpVtbl->remove_ContentLoading(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_DOMContentLoaded(This,handler,token) \
    ( (This)->lpVtbl->add_DOMContentLoaded(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_DOMContentLoaded(This,token) \
    ( (This)->lpVtbl->remove_DOMContentLoaded(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_NavigationCompleted(This,handler,token) \
    ( (This)->lpVtbl->add_NavigationCompleted(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_NavigationCompleted(This,token) \
    ( (This)->lpVtbl->remove_NavigationCompleted(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_FrameNavigationStarting(This,handler,token) \
    ( (This)->lpVtbl->add_FrameNavigationStarting(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_FrameNavigationStarting(This,token) \
    ( (This)->lpVtbl->remove_FrameNavigationStarting(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_FrameContentLoading(This,handler,token) \
    ( (This)->lpVtbl->add_FrameContentLoading(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_FrameContentLoading(This,token) \
    ( (This)->lpVtbl->remove_FrameContentLoading(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_FrameDOMContentLoaded(This,handler,token) \
    ( (This)->lpVtbl->add_FrameDOMContentLoaded(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_FrameDOMContentLoaded(This,token) \
    ( (This)->lpVtbl->remove_FrameDOMContentLoaded(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_FrameNavigationCompleted(This,handler,token) \
    ( (This)->lpVtbl->add_FrameNavigationCompleted(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_FrameNavigationCompleted(This,token) \
    ( (This)->lpVtbl->remove_FrameNavigationCompleted(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_ScriptNotify(This,handler,token) \
    ( (This)->lpVtbl->add_ScriptNotify(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_ScriptNotify(This,token) \
    ( (This)->lpVtbl->remove_ScriptNotify(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_LongRunningScriptDetected(This,handler,token) \
    ( (This)->lpVtbl->add_LongRunningScriptDetected(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_LongRunningScriptDetected(This,token) \
    ( (This)->lpVtbl->remove_LongRunningScriptDetected(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_UnsafeContentWarningDisplaying(This,handler,token) \
    ( (This)->lpVtbl->add_UnsafeContentWarningDisplaying(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_UnsafeContentWarningDisplaying(This,token) \
    ( (This)->lpVtbl->remove_UnsafeContentWarningDisplaying(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_UnviewableContentIdentified(This,handler,token) \
    ( (This)->lpVtbl->add_UnviewableContentIdentified(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_UnviewableContentIdentified(This,token) \
    ( (This)->lpVtbl->remove_UnviewableContentIdentified(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_PermissionRequested(This,handler,token) \
    ( (This)->lpVtbl->add_PermissionRequested(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_PermissionRequested(This,token) \
    ( (This)->lpVtbl->remove_PermissionRequested(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_UnsupportedUriSchemeIdentified(This,handler,token) \
    ( (This)->lpVtbl->add_UnsupportedUriSchemeIdentified(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_UnsupportedUriSchemeIdentified(This,token) \
    ( (This)->lpVtbl->remove_UnsupportedUriSchemeIdentified(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_NewWindowRequested(This,handler,token) \
    ( (This)->lpVtbl->add_NewWindowRequested(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_NewWindowRequested(This,token) \
    ( (This)->lpVtbl->remove_NewWindowRequested(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_ContainsFullScreenElementChanged(This,handler,token) \
    ( (This)->lpVtbl->add_ContainsFullScreenElementChanged(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_ContainsFullScreenElementChanged(This,token) \
    ( (This)->lpVtbl->remove_ContainsFullScreenElementChanged(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_add_WebResourceRequested(This,handler,token) \
    ( (This)->lpVtbl->add_WebResourceRequested(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl_remove_WebResourceRequested(This,token) \
    ( (This)->lpVtbl->remove_WebResourceRequested(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControl;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControl2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControl2[] = L"Windows.Web.UI.IWebViewControl2";
/* [object, uuid("4D3C06F9-C8DF-41CC-8BD5-2A947B204503"), contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *AddInitializeScript )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 * This,
        /* [in] */__RPC__in HSTRING script
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2Vtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_AddInitializeScript(This,script) \
    ( (This)->lpVtbl->AddInitializeScript(This,script) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControl2;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlContentLoadingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlContentLoadingEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlContentLoadingEventArgs[] = L"Windows.Web.UI.IWebViewControlContentLoadingEventArgs";
/* [object, uuid("9A3FCCB2-B9BB-404B-A22B-66DCCD1250C6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlContentLoadingEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlDOMContentLoadedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlDOMContentLoadedEventArgs[] = L"Windows.Web.UI.IWebViewControlDOMContentLoadedEventArgs";
/* [object, uuid("BE8BC008-9541-4545-9FF2-2DF585B29F7D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDOMContentLoadedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlDeferredPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlDeferredPermissionRequest
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlDeferredPermissionRequest[] = L"Windows.Web.UI.IWebViewControlDeferredPermissionRequest";
/* [object, uuid("2CE349E0-D759-445C-9926-8995298F152B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequestVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PermissionType )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionType * value
        );
    HRESULT ( STDMETHODCALLTYPE *Allow )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This
        );
    HRESULT ( STDMETHODCALLTYPE *Deny )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequestVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequestVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_get_PermissionType(This,value) \
    ( (This)->lpVtbl->get_PermissionType(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_Allow(This) \
    ( (This)->lpVtbl->Allow(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_Deny(This) \
    ( (This)->lpVtbl->Deny(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlDeferredPermissionRequest_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlLongRunningScriptDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs[] = L"Windows.Web.UI.IWebViewControlLongRunningScriptDetectedEventArgs";
/* [object, uuid("2A6E5BBA-98B4-45BC-BBEB-0F69CE49C599"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExecutionTime )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StopPageScriptExecution )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StopPageScriptExecution )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_get_ExecutionTime(This,value) \
    ( (This)->lpVtbl->get_ExecutionTime(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_get_StopPageScriptExecution(This,value) \
    ( (This)->lpVtbl->get_StopPageScriptExecution(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_put_StopPageScriptExecution(This,value) \
    ( (This)->lpVtbl->put_StopPageScriptExecution(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlLongRunningScriptDetectedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNavigationCompletedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNavigationCompletedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs[] = L"Windows.Web.UI.IWebViewControlNavigationCompletedEventArgs";
/* [object, uuid("20409918-4A15-4C46-A55D-F79EDB0BDE8B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsSuccess )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WebErrorStatus )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CWebErrorStatus * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_get_IsSuccess(This,value) \
    ( (This)->lpVtbl->get_IsSuccess(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_get_WebErrorStatus(This,value) \
    ( (This)->lpVtbl->get_WebErrorStatus(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationCompletedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNavigationStartingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNavigationStartingEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs[] = L"Windows.Web.UI.IWebViewControlNavigationStartingEventArgs";
/* [object, uuid("0C9057C5-0A08-41C7-863B-71E3A9549137"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Cancel )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Cancel )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_get_Cancel(This,value) \
    ( (This)->lpVtbl->get_Cancel(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_put_Cancel(This,value) \
    ( (This)->lpVtbl->put_Cancel(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNavigationStartingEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs[] = L"Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs";
/* [object, uuid("3DF44BBB-A124-46D5-A083-D02CACDFF5AD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Referrer )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_get_Referrer(This,value) \
    ( (This)->lpVtbl->get_Referrer(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2[] = L"Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs2";
/* [object, uuid("B53C5CA6-2AAE-4BFC-92B9-C30E92B48098"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NewWindow )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_NewWindow )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * deferral
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2Vtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_get_NewWindow(This,value) \
    ( (This)->lpVtbl->get_NewWindow(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_put_NewWindow(This,value) \
    ( (This)->lpVtbl->put_NewWindow(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_GetDeferral(This,deferral) \
    ( (This)->lpVtbl->GetDeferral(This,deferral) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlNewWindowRequestedEventArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlPermissionRequest
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlPermissionRequest[] = L"Windows.Web.UI.IWebViewControlPermissionRequest";
/* [object, uuid("E5BC836C-F22F-40E2-95B2-7729F840EB7F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PermissionType )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionType * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_State )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CUI_CWebViewControlPermissionState * value
        );
    HRESULT ( STDMETHODCALLTYPE *Defer )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This
        );
    HRESULT ( STDMETHODCALLTYPE *Allow )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This
        );
    HRESULT ( STDMETHODCALLTYPE *Deny )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_get_PermissionType(This,value) \
    ( (This)->lpVtbl->get_PermissionType(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_get_State(This,value) \
    ( (This)->lpVtbl->get_State(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_Defer(This) \
    ( (This)->lpVtbl->Defer(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_Allow(This) \
    ( (This)->lpVtbl->Allow(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_Deny(This) \
    ( (This)->lpVtbl->Deny(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlPermissionRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlPermissionRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlPermissionRequestedEventArgs[] = L"Windows.Web.UI.IWebViewControlPermissionRequestedEventArgs";
/* [object, uuid("27204D51-2488-4CC5-968E-0A771E59C147"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PermissionRequest )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequest * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_get_PermissionRequest(This,value) \
    ( (This)->lpVtbl->get_PermissionRequest(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlPermissionRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlScriptNotifyEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlScriptNotifyEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlScriptNotifyEventArgs[] = L"Windows.Web.UI.IWebViewControlScriptNotifyEventArgs";
/* [object, uuid("491DE57B-6F49-41BB-B591-51B85B817037"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Value )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_get_Value(This,value) \
    ( (This)->lpVtbl->get_Value(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlScriptNotifyEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlSettings[] = L"Windows.Web.UI.IWebViewControlSettings";
/* [object, uuid("C9967FBF-5E98-4CFD-8CCE-27B0911E3DE8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsJavaScriptEnabled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsJavaScriptEnabled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsIndexedDBEnabled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsIndexedDBEnabled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsScriptNotifyAllowed )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsScriptNotifyAllowed )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettingsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_put_IsJavaScriptEnabled(This,value) \
    ( (This)->lpVtbl->put_IsJavaScriptEnabled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_get_IsJavaScriptEnabled(This,value) \
    ( (This)->lpVtbl->get_IsJavaScriptEnabled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_put_IsIndexedDBEnabled(This,value) \
    ( (This)->lpVtbl->put_IsIndexedDBEnabled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_get_IsIndexedDBEnabled(This,value) \
    ( (This)->lpVtbl->get_IsIndexedDBEnabled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_put_IsScriptNotifyAllowed(This,value) \
    ( (This)->lpVtbl->put_IsScriptNotifyAllowed(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_get_IsScriptNotifyAllowed(This,value) \
    ( (This)->lpVtbl->get_IsScriptNotifyAllowed(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs[] = L"Windows.Web.UI.IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs";
/* [object, uuid("E3B81944-E4FC-43DC-94CA-F980F30BC51D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnsupportedUriSchemeIdentifiedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlUnviewableContentIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs[] = L"Windows.Web.UI.IWebViewControlUnviewableContentIdentifiedEventArgs";
/* [object, uuid("4A9680DB-88F2-4E20-B693-B4E2DF4AA581"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Uri )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Referrer )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIUriRuntimeClass * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MediaType )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_get_Uri(This,value) \
    ( (This)->lpVtbl->get_Uri(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_get_Referrer(This,value) \
    ( (This)->lpVtbl->get_Referrer(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_get_MediaType(This,value) \
    ( (This)->lpVtbl->get_MediaType(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlUnviewableContentIdentifiedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.IWebViewControlWebResourceRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs[] = L"Windows.Web.UI.IWebViewControlWebResourceRequestedEventArgs";
/* [object, uuid("44D6524D-55A4-4D8B-891C-931D8E25D42E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * deferral
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Request )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CHttp_CIHttpRequestMessage * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Response )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Response )(
        __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CHttp_CIHttpResponseMessage * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_GetDeferral(This,deferral) \
    ( (This)->lpVtbl->GetDeferral(This,deferral) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_get_Request(This,value) \
    ( (This)->lpVtbl->get_Request(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_put_Response(This,value) \
    ( (This)->lpVtbl->put_Response(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_get_Response(This,value) \
    ( (This)->lpVtbl->get_Response(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CIWebViewControlWebResourceRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlContentLoadingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlContentLoadingEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlContentLoadingEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlContentLoadingEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlContentLoadingEventArgs[] = L"Windows.Web.UI.WebViewControlContentLoadingEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlDOMContentLoadedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlDOMContentLoadedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlDOMContentLoadedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlDOMContentLoadedEventArgs[] = L"Windows.Web.UI.WebViewControlDOMContentLoadedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlDeferredPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlDeferredPermissionRequest ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlDeferredPermissionRequest_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlDeferredPermissionRequest_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlDeferredPermissionRequest[] = L"Windows.Web.UI.WebViewControlDeferredPermissionRequest";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlLongRunningScriptDetectedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlLongRunningScriptDetectedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlLongRunningScriptDetectedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlLongRunningScriptDetectedEventArgs[] = L"Windows.Web.UI.WebViewControlLongRunningScriptDetectedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlNavigationCompletedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlNavigationCompletedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationCompletedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationCompletedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlNavigationCompletedEventArgs[] = L"Windows.Web.UI.WebViewControlNavigationCompletedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlNavigationStartingEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlNavigationStartingEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationStartingEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlNavigationStartingEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlNavigationStartingEventArgs[] = L"Windows.Web.UI.WebViewControlNavigationStartingEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs ** Default Interface **
 *    Windows.Web.UI.IWebViewControlNewWindowRequestedEventArgs2
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlNewWindowRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlNewWindowRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlNewWindowRequestedEventArgs[] = L"Windows.Web.UI.WebViewControlNewWindowRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlPermissionRequest
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlPermissionRequest ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequest_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequest_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlPermissionRequest[] = L"Windows.Web.UI.WebViewControlPermissionRequest";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlPermissionRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlPermissionRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlPermissionRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlPermissionRequestedEventArgs[] = L"Windows.Web.UI.WebViewControlPermissionRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlScriptNotifyEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlScriptNotifyEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlScriptNotifyEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlScriptNotifyEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlScriptNotifyEventArgs[] = L"Windows.Web.UI.WebViewControlScriptNotifyEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlSettings_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlSettings[] = L"Windows.Web.UI.WebViewControlSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlUnsupportedUriSchemeIdentifiedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlUnsupportedUriSchemeIdentifiedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlUnsupportedUriSchemeIdentifiedEventArgs[] = L"Windows.Web.UI.WebViewControlUnsupportedUriSchemeIdentifiedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlUnviewableContentIdentifiedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlUnviewableContentIdentifiedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlUnviewableContentIdentifiedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlUnviewableContentIdentifiedEventArgs[] = L"Windows.Web.UI.WebViewControlUnviewableContentIdentifiedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControlWebResourceRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_WebViewControlWebResourceRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_WebViewControlWebResourceRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_WebViewControlWebResourceRequestedEventArgs[] = L"Windows.Web.UI.WebViewControlWebResourceRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eweb2Eui_p_h__

#endif // __windows2Eweb2Eui_h__
