/* Header file automatically generated from windows.ui.windowmanagement.idl */
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
#ifndef __windows2Eui2Ewindowmanagement_h__
#define __windows2Eui2Ewindowmanagement_h__
#ifndef __windows2Eui2Ewindowmanagement_p_h__
#define __windows2Eui2Ewindowmanagement_p_h__


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
#include "Windows.System.h"
#include "Windows.UI.h"
#include "Windows.UI.Composition.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindow;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow ABI::Windows::UI::WindowManagement::IAppWindow

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowChangedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs ABI::Windows::UI::WindowManagement::IAppWindowChangedEventArgs

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowCloseRequestedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs ABI::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowClosedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs ABI::Windows::UI::WindowManagement::IAppWindowClosedEventArgs

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowFrame;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame ABI::Windows::UI::WindowManagement::IAppWindowFrame

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowFrameStyle;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle ABI::Windows::UI::WindowManagement::IAppWindowFrameStyle

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowPlacement;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement ABI::Windows::UI::WindowManagement::IAppWindowPlacement

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration ABI::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowPresentationConfigurationFactory;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory ABI::Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowPresenter;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter ABI::Windows::UI::WindowManagement::IAppWindowPresenter

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowStatics;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics ABI::Windows::UI::WindowManagement::IAppWindowStatics

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowTitleBar;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar ABI::Windows::UI::WindowManagement::IAppWindowTitleBar

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowTitleBarOcclusion;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IAppWindowTitleBarVisibility;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility ABI::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface ICompactOverlayPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration ABI::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IDefaultPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration ABI::Windows::UI::WindowManagement::IDefaultPresentationConfiguration

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IDisplayRegion;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion ABI::Windows::UI::WindowManagement::IDisplayRegion

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IFullScreenPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration ABI::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IWindowingEnvironment;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment ABI::Windows::UI::WindowManagement::IWindowingEnvironment

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IWindowingEnvironmentAddedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs ABI::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IWindowingEnvironmentChangedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs ABI::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IWindowingEnvironmentRemovedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs ABI::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                interface IWindowingEnvironmentStatics;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics ABI::Windows::UI::WindowManagement::IWindowingEnvironmentStatics

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowTitleBarOcclusion;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE
#define DEF___FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("13e952db-f553-5c43-8fd2-0e1b9df3ee3f"))
IIterator<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*, ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.WindowManagement.AppWindowTitleBarOcclusion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*> __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t;
#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>
//#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE
#define DEF___FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("3503c7c3-d036-5152-92dd-de9732205420"))
IIterable<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*, ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.WindowManagement.AppWindowTitleBarOcclusion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*> __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t;
#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>
//#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class DisplayRegion;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE
#define DEF___FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("110d4d7e-2f29-51b8-9691-8b206ad1d73b"))
IIterator<ABI::Windows::UI::WindowManagement::DisplayRegion*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::DisplayRegion*, ABI::Windows::UI::WindowManagement::IDisplayRegion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.WindowManagement.DisplayRegion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::WindowManagement::DisplayRegion*> __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_t;
#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::WindowManagement::IDisplayRegion*>
//#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::WindowManagement::IDisplayRegion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE
#define DEF___FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("026730ab-250d-503c-a876-43bbb754ad44"))
IIterable<ABI::Windows::UI::WindowManagement::DisplayRegion*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::DisplayRegion*, ABI::Windows::UI::WindowManagement::IDisplayRegion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.WindowManagement.DisplayRegion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::WindowManagement::DisplayRegion*> __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_t;
#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::WindowManagement::IDisplayRegion*>
//#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::WindowManagement::IDisplayRegion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class WindowingEnvironment;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE
#define DEF___FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("a35c192a-9459-5bcc-9db3-23243716197f"))
IIterator<ABI::Windows::UI::WindowManagement::WindowingEnvironment*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::WindowingEnvironment*, ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.WindowManagement.WindowingEnvironment>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::WindowManagement::WindowingEnvironment*> __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t;
#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>
//#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE
#define DEF___FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("626a6481-0174-5a56-84c9-e8d4c48cfb1b"))
IIterable<ABI::Windows::UI::WindowManagement::WindowingEnvironment*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::WindowingEnvironment*, ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.WindowManagement.WindowingEnvironment>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::WindowManagement::WindowingEnvironment*> __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t;
#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>
//#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE
#define DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("586d5577-7d02-5c77-bb43-39522f80972e"))
IVectorView<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*, ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.WindowManagement.AppWindowTitleBarOcclusion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion*> __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t;
#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>
//#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE
#define DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("9460debb-a0d6-5ab8-84f5-9087f2a6bb67"))
IVectorView<ABI::Windows::UI::WindowManagement::DisplayRegion*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::DisplayRegion*, ABI::Windows::UI::WindowManagement::IDisplayRegion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.WindowManagement.DisplayRegion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::WindowManagement::DisplayRegion*> __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_t;
#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::WindowManagement::IDisplayRegion*>
//#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::WindowManagement::IDisplayRegion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE
#define DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("c833c1c0-79c6-522e-b71b-d845e0f6668e"))
IVectorView<ABI::Windows::UI::WindowManagement::WindowingEnvironment*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::WindowingEnvironment*, ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.WindowManagement.WindowingEnvironment>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::WindowManagement::WindowingEnvironment*> __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t;
#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>
//#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindow;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3bbea3e6-34b8-5ef0-a093-9cc71fa40b6e"))
IAsyncOperationCompletedHandler<ABI::Windows::UI::WindowManagement::AppWindow*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindow*, ABI::Windows::UI::WindowManagement::IAppWindow*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.UI.WindowManagement.AppWindow>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::UI::WindowManagement::AppWindow*> __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::UI::WindowManagement::IAppWindow*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::UI::WindowManagement::IAppWindow*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_USE
#define DEF___FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("4167727a-5df0-5ed3-b624-167c81beff6b"))
IAsyncOperation<ABI::Windows::UI::WindowManagement::AppWindow*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindow*, ABI::Windows::UI::WindowManagement::IAppWindow*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.UI.WindowManagement.AppWindow>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::UI::WindowManagement::AppWindow*> __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_t;
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::UI::WindowManagement::IAppWindow*>
//#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::UI::WindowManagement::IAppWindow*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowChangedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c6a30887-6f60-597f-b918-757cab5f3a76"))
ITypedEventHandler<ABI::Windows::UI::WindowManagement::AppWindow*,ABI::Windows::UI::WindowManagement::AppWindowChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindow*, ABI::Windows::UI::WindowManagement::IAppWindow*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindowChangedEventArgs*, ABI::Windows::UI::WindowManagement::IAppWindowChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.WindowManagement.AppWindow, Windows.UI.WindowManagement.AppWindowChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::WindowManagement::AppWindow*,ABI::Windows::UI::WindowManagement::AppWindowChangedEventArgs*> __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IAppWindow*,ABI::Windows::UI::WindowManagement::IAppWindowChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IAppWindow*,ABI::Windows::UI::WindowManagement::IAppWindowChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowCloseRequestedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c0359718-173d-5f19-b76a-91929b2b0451"))
ITypedEventHandler<ABI::Windows::UI::WindowManagement::AppWindow*,ABI::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindow*, ABI::Windows::UI::WindowManagement::IAppWindow*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs*, ABI::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.WindowManagement.AppWindow, Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::WindowManagement::AppWindow*,ABI::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs*> __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IAppWindow*,ABI::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IAppWindow*,ABI::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowClosedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7f62c430-89b3-5873-93ca-bb4d71a390e4"))
ITypedEventHandler<ABI::Windows::UI::WindowManagement::AppWindow*,ABI::Windows::UI::WindowManagement::AppWindowClosedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindow*, ABI::Windows::UI::WindowManagement::IAppWindow*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::AppWindowClosedEventArgs*, ABI::Windows::UI::WindowManagement::IAppWindowClosedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.WindowManagement.AppWindow, Windows.UI.WindowManagement.AppWindowClosedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::WindowManagement::AppWindow*,ABI::Windows::UI::WindowManagement::AppWindowClosedEventArgs*> __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IAppWindow*,ABI::Windows::UI::WindowManagement::IAppWindowClosedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IAppWindow*,ABI::Windows::UI::WindowManagement::IAppWindowClosedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2c40d18b-7438-5eb4-9359-7897fce7e3fc"))
ITypedEventHandler<ABI::Windows::UI::WindowManagement::DisplayRegion*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::DisplayRegion*, ABI::Windows::UI::WindowManagement::IDisplayRegion*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.WindowManagement.DisplayRegion, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::WindowManagement::DisplayRegion*,IInspectable*> __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IDisplayRegion*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IDisplayRegion*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class WindowingEnvironmentChangedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3af2bd46-4225-5a93-85ed-73a01e91d0b5"))
ITypedEventHandler<ABI::Windows::UI::WindowManagement::WindowingEnvironment*,ABI::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::WindowingEnvironment*, ABI::Windows::UI::WindowManagement::IWindowingEnvironment*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs*, ABI::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.WindowManagement.WindowingEnvironment, Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::WindowManagement::WindowingEnvironment*,ABI::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs*> __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*,ABI::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::WindowManagement::IWindowingEnvironment*,ABI::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


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



#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface IVisualElement;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CIVisualElement ABI::Windows::UI::Composition::IVisualElement

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CIVisualElement_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CIVisualElement_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("3142fdb3-4110-5819-b966-9c2a172e209f"))
IIterator<ABI::Windows::UI::Composition::IVisualElement*> : IIterator_impl<ABI::Windows::UI::Composition::IVisualElement*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.IVisualElement>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::IVisualElement*> __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_t;
#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CIVisualElement_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::IVisualElement*>
//#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::IVisualElement*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CIVisualElement_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CIVisualElement_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CIVisualElement_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("a0394077-1a66-589c-997d-2acba9051f77"))
IIterable<ABI::Windows::UI::Composition::IVisualElement*> : IIterable_impl<ABI::Windows::UI::Composition::IVisualElement*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.IVisualElement>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::IVisualElement*> __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_t;
#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CIVisualElement_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::IVisualElement*>
//#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::IVisualElement*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CIVisualElement_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_USE
#define DEF___FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("48e605a6-1fa6-5b4b-a802-17f54c4bcccc"))
IVectorView<ABI::Windows::UI::Composition::IVisualElement*> : IVectorView_impl<ABI::Windows::UI::Composition::IVisualElement*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.Composition.IVisualElement>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::Composition::IVisualElement*> __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_t;
#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Composition::IVisualElement*>
//#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Composition::IVisualElement*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVector_1_Windows__CUI__CComposition__CIVisualElement_USE
#define DEF___FIVector_1_Windows__CUI__CComposition__CIVisualElement_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("cf59c70b-6d34-55fb-9313-9781433e778a"))
IVector<ABI::Windows::UI::Composition::IVisualElement*> : IVector_impl<ABI::Windows::UI::Composition::IVisualElement*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<Windows.UI.Composition.IVisualElement>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<ABI::Windows::UI::Composition::IVisualElement*> __FIVector_1_Windows__CUI__CComposition__CIVisualElement_t;
#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::__FIVector_1_Windows__CUI__CComposition__CIVisualElement_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement ABI::Windows::Foundation::Collections::IVector<ABI::Windows::UI::Composition::IVisualElement*>
//#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_t ABI::Windows::Foundation::Collections::IVector<ABI::Windows::UI::Composition::IVisualElement*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_Windows__CUI__CComposition__CIVisualElement_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

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
            
            typedef struct Point Point;
            
        } /* Foundation */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Rect Rect;
            
        } /* Foundation */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Size Size;
            
        } /* Foundation */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace System {
            class DispatcherQueue;
        } /* System */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            interface IDispatcherQueue;
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CIDispatcherQueue ABI::Windows::System::IDispatcherQueue

#endif // ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__




namespace ABI {
    namespace Windows {
        namespace UI {
            
            typedef struct Color Color;
            
        } /* UI */
    } /* Windows */} /* ABI */







namespace ABI {
    namespace Windows {
        namespace UI {
            class UIContentRoot;
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CIUIContentRoot_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CIUIContentRoot_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            interface IUIContentRoot;
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CIUIContentRoot ABI::Windows::UI::IUIContentRoot

#endif // ____x_ABI_CWindows_CUI_CIUIContentRoot_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace UI {
            class UIContext;
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            interface IUIContext;
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CIUIContext ABI::Windows::UI::IUIContext

#endif // ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__




namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                
                typedef enum AppWindowClosedReason : int AppWindowClosedReason;
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                
                typedef enum AppWindowFrameStyle : int AppWindowFrameStyle;
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                
                typedef enum AppWindowPresentationKind : int AppWindowPresentationKind;
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                
                typedef enum AppWindowTitleBarVisibility : int AppWindowTitleBarVisibility;
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                
                typedef enum WindowingEnvironmentKind : int WindowingEnvironmentKind;
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */




























namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowFrame;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowPlacement;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowPresenter;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindowTitleBar;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class CompactOverlayPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class DefaultPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class FullScreenPresentationConfiguration;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class WindowingEnvironmentAddedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class WindowingEnvironmentRemovedEventArgs;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */










/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowClosedReason
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [v1_enum, contract] */
                enum AppWindowClosedReason : int
                {
                    AppWindowClosedReason_Other = 0,
                    AppWindowClosedReason_AppInitiated = 1,
                    AppWindowClosedReason_UserInitiated = 2,
                };
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowFrameStyle
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [v1_enum, contract] */
                enum AppWindowFrameStyle : int
                {
                    AppWindowFrameStyle_Default = 0,
                    AppWindowFrameStyle_NoFrame = 1,
                };
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowPresentationKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [v1_enum, contract] */
                enum AppWindowPresentationKind : int
                {
                    AppWindowPresentationKind_Default = 0,
                    AppWindowPresentationKind_CompactOverlay = 1,
                    AppWindowPresentationKind_FullScreen = 2,
                };
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowTitleBarVisibility
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [v1_enum, contract] */
                enum AppWindowTitleBarVisibility : int
                {
                    AppWindowTitleBarVisibility_Default = 0,
                    AppWindowTitleBarVisibility_AlwaysHidden = 1,
                };
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.WindowingEnvironmentKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [v1_enum, contract] */
                enum WindowingEnvironmentKind : int
                {
                    WindowingEnvironmentKind_Unknown = 0,
                    WindowingEnvironmentKind_Overlapped = 1,
                    WindowingEnvironmentKind_Tiled = 2,
                };
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindow
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindow
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindow[] = L"Windows.UI.WindowManagement.IAppWindow";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("663014A6-B75E-5DBD-995C-F0117FA3FB61"), exclusiveto, contract] */
                MIDL_INTERFACE("663014A6-B75E-5DBD-995C-F0117FA3FB61")
                IAppWindow : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Content(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::IUIContentRoot * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DispatcherQueue(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::System::IDispatcherQueue * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Frame(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IAppWindowFrame * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVisible(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PersistedStateId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PersistedStateId(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Presenter(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IAppWindowPresenter * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Title(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Title(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TitleBar(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IAppWindowTitleBar * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UIContext(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::IUIContext * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WindowingEnvironment(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IWindowingEnvironment * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CloseAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetPlacement(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IAppWindowPlacement * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDisplayRegions(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMoveToDisplayRegion(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::WindowManagement::IDisplayRegion * displayRegion
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMoveAdjacentToCurrentView(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMoveAdjacentToWindow(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::WindowManagement::IAppWindow * anchorWindow
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMoveRelativeToWindowContent(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::WindowManagement::IAppWindow * anchorWindow,
                        /* [in] */ABI::Windows::Foundation::Point contentOffset
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMoveRelativeToCurrentViewContent(
                        /* [in] */ABI::Windows::Foundation::Point contentOffset
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestMoveRelativeToDisplayRegion(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::WindowManagement::IDisplayRegion * displayRegion,
                        /* [in] */ABI::Windows::Foundation::Point displayRegionOffset
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestSize(
                        /* [in] */ABI::Windows::Foundation::Size frameSize
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryShowAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Changed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Changed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Closed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Closed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_CloseRequested(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_CloseRequested(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindow=_uuidof(IAppWindow);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowChangedEventArgs[] = L"Windows.UI.WindowManagement.IAppWindowChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("1DE1F3BE-A655-55AD-B2B6-EB240F880356"), exclusiveto, contract] */
                MIDL_INTERFACE("1DE1F3BE-A655-55AD-B2B6-EB240F880356")
                IAppWindowChangedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidAvailableWindowPresentationsChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidDisplayRegionsChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidFrameChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidSizeChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidTitleBarChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidVisibilityChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidWindowingEnvironmentChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DidWindowPresentationChange(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowChangedEventArgs=_uuidof(IAppWindowChangedEventArgs);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowCloseRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs[] = L"Windows.UI.WindowManagement.IAppWindowCloseRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("E9FF01DA-E7A2-57A8-8B5E-39C4003AFDBB"), exclusiveto, contract] */
                MIDL_INTERFACE("E9FF01DA-E7A2-57A8-8B5E-39C4003AFDBB")
                IAppWindowCloseRequestedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Cancel(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Cancel(
                        /* [in] */::boolean value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowCloseRequestedEventArgs=_uuidof(IAppWindowCloseRequestedEventArgs);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowClosedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowClosedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowClosedEventArgs[] = L"Windows.UI.WindowManagement.IAppWindowClosedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("CC7DF816-9520-5A06-821E-456AD8B358AA"), exclusiveto, contract] */
                MIDL_INTERFACE("CC7DF816-9520-5A06-821E-456AD8B358AA")
                IAppWindowClosedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Reason(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::WindowManagement::AppWindowClosedReason * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowClosedEventArgs=_uuidof(IAppWindowClosedEventArgs);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowFrame
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowFrame[] = L"Windows.UI.WindowManagement.IAppWindowFrame";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("9EE22601-7E5D-52AF-846B-01DC6C296567"), exclusiveto, contract] */
                MIDL_INTERFACE("9EE22601-7E5D-52AF-846B-01DC6C296567")
                IAppWindowFrame : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DragRegionVisuals(
                        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CUI__CComposition__CIVisualElement * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowFrame=_uuidof(IAppWindowFrame);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowFrameStyle
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowFrame
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowFrameStyle[] = L"Windows.UI.WindowManagement.IAppWindowFrameStyle";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("AC412946-E1AC-5230-944A-C60873DCF4A9"), exclusiveto, contract] */
                MIDL_INTERFACE("AC412946-E1AC-5230-944A-C60873DCF4A9")
                IAppWindowFrameStyle : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetFrameStyle(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::WindowManagement::AppWindowFrameStyle * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetFrameStyle(
                        /* [in] */ABI::Windows::UI::WindowManagement::AppWindowFrameStyle frameStyle
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowFrameStyle=_uuidof(IAppWindowFrameStyle);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPlacement
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPlacement
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPlacement[] = L"Windows.UI.WindowManagement.IAppWindowPlacement";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("03DC815E-E7A9-5857-9C03-7D670594410E"), exclusiveto, contract] */
                MIDL_INTERFACE("03DC815E-E7A9-5857-9C03-7D670594410E")
                IAppWindowPlacement : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayRegion(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IDisplayRegion * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Offset(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Size(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Size * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowPlacement=_uuidof(IAppWindowPlacement);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPresentationConfiguration[] = L"Windows.UI.WindowManagement.IAppWindowPresentationConfiguration";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("B5A43EE3-DF33-5E67-BD31-1072457300DF"), exclusiveto, contract] */
                MIDL_INTERFACE("B5A43EE3-DF33-5E67-BD31-1072457300DF")
                IAppWindowPresentationConfiguration : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Kind(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::WindowManagement::AppWindowPresentationKind * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowPresentationConfiguration=_uuidof(IAppWindowPresentationConfiguration);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPresentationConfigurationFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPresentationConfigurationFactory[] = L"Windows.UI.WindowManagement.IAppWindowPresentationConfigurationFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("FD3606A6-7875-5DE8-84FF-6351EE13DD0D"), exclusiveto, contract] */
                MIDL_INTERFACE("FD3606A6-7875-5DE8-84FF-6351EE13DD0D")
                IAppWindowPresentationConfigurationFactory : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowPresentationConfigurationFactory=_uuidof(IAppWindowPresentationConfigurationFactory);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPresenter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPresenter
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPresenter[] = L"Windows.UI.WindowManagement.IAppWindowPresenter";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("5AE9ED73-E1FD-5317-AD78-5A3ED271BBDE"), exclusiveto, contract] */
                MIDL_INTERFACE("5AE9ED73-E1FD-5317-AD78-5A3ED271BBDE")
                IAppWindowPresenter : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetConfiguration(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE IsPresentationSupported(
                        /* [in] */ABI::Windows::UI::WindowManagement::AppWindowPresentationKind presentationKind,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE RequestPresentation(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration * configuration,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    /* [overload, default_overload] */virtual HRESULT STDMETHODCALLTYPE RequestPresentationByKind(
                        /* [in] */ABI::Windows::UI::WindowManagement::AppWindowPresentationKind presentationKind,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowPresenter=_uuidof(IAppWindowPresenter);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindow
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowStatics[] = L"Windows.UI.WindowManagement.IAppWindowStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("FF1F3EA3-B769-50EF-9873-108CD0E89746"), exclusiveto, contract] */
                MIDL_INTERFACE("FF1F3EA3-B769-50EF-9873-108CD0E89746")
                IAppWindowStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE TryCreateAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ClearAllPersistedState(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ClearPersistedState(
                        /* [in] */__RPC__in HSTRING key
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowStatics=_uuidof(IAppWindowStatics);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowTitleBar
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowTitleBar
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowTitleBar[] = L"Windows.UI.WindowManagement.IAppWindowTitleBar";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("6E932C84-F644-541D-A2D7-0C262437842D"), exclusiveto, contract] */
                MIDL_INTERFACE("6E932C84-F644-541D-A2D7-0C262437842D")
                IAppWindowTitleBar : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BackgroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BackgroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonBackgroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonBackgroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonForegroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonForegroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonHoverBackgroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonHoverBackgroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonHoverForegroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonHoverForegroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonInactiveBackgroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonInactiveBackgroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonInactiveForegroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonInactiveForegroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonPressedBackgroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonPressedBackgroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ButtonPressedForegroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ButtonPressedForegroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendsContentIntoTitleBar(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ExtendsContentIntoTitleBar(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ForegroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ForegroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InactiveBackgroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_InactiveBackgroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InactiveForegroundColor(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_InactiveForegroundColor(
                        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVisible(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetTitleBarOcclusions(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowTitleBar=_uuidof(IAppWindowTitleBar);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowTitleBarOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowTitleBarOcclusion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowTitleBarOcclusion[] = L"Windows.UI.WindowManagement.IAppWindowTitleBarOcclusion";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("FEA3CFFD-2CCF-5FC3-AEAE-F843876BF37E"), exclusiveto, contract] */
                MIDL_INTERFACE("FEA3CFFD-2CCF-5FC3-AEAE-F843876BF37E")
                IAppWindowTitleBarOcclusion : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OccludingRect(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Rect * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowTitleBarOcclusion=_uuidof(IAppWindowTitleBarOcclusion);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowTitleBarVisibility
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowTitleBar
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowTitleBarVisibility[] = L"Windows.UI.WindowManagement.IAppWindowTitleBarVisibility";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("A215A4E3-6E7E-5651-8C3B-624819528154"), exclusiveto, contract] */
                MIDL_INTERFACE("A215A4E3-6E7E-5651-8C3B-624819528154")
                IAppWindowTitleBarVisibility : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetPreferredVisibility(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::WindowManagement::AppWindowTitleBarVisibility * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetPreferredVisibility(
                        /* [in] */ABI::Windows::UI::WindowManagement::AppWindowTitleBarVisibility visibilityMode
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAppWindowTitleBarVisibility=_uuidof(IAppWindowTitleBarVisibility);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.ICompactOverlayPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.CompactOverlayPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_ICompactOverlayPresentationConfiguration[] = L"Windows.UI.WindowManagement.ICompactOverlayPresentationConfiguration";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("A7E5750F-5730-56C6-8E1F-D63FF4D7980D"), exclusiveto, contract] */
                MIDL_INTERFACE("A7E5750F-5730-56C6-8E1F-D63FF4D7980D")
                ICompactOverlayPresentationConfiguration : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_ICompactOverlayPresentationConfiguration=_uuidof(ICompactOverlayPresentationConfiguration);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IDefaultPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.DefaultPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IDefaultPresentationConfiguration[] = L"Windows.UI.WindowManagement.IDefaultPresentationConfiguration";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("D8C2B53B-2168-5703-A853-D525589FE2B9"), exclusiveto, contract] */
                MIDL_INTERFACE("D8C2B53B-2168-5703-A853-D525589FE2B9")
                IDefaultPresentationConfiguration : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IDefaultPresentationConfiguration=_uuidof(IDefaultPresentationConfiguration);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IDisplayRegion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.DisplayRegion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IDisplayRegion[] = L"Windows.UI.WindowManagement.IDisplayRegion";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("DB50C3A2-4094-5F47-8CB1-EA01DDAFAA94"), exclusiveto, contract] */
                MIDL_INTERFACE("DB50C3A2-4094-5F47-8CB1-EA01DDAFAA94")
                IDisplayRegion : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayMonitorDeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVisible(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WorkAreaOffset(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WorkAreaSize(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Size * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WindowingEnvironment(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IWindowingEnvironment * * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Changed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Changed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayRegion=_uuidof(IDisplayRegion);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IFullScreenPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.FullScreenPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IFullScreenPresentationConfiguration[] = L"Windows.UI.WindowManagement.IFullScreenPresentationConfiguration";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("43D3DCD8-D2A8-503D-A626-15533D6D5F62"), exclusiveto, contract] */
                MIDL_INTERFACE("43D3DCD8-D2A8-503D-A626-15533D6D5F62")
                IFullScreenPresentationConfiguration : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsExclusive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsExclusive(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IFullScreenPresentationConfiguration=_uuidof(IFullScreenPresentationConfiguration);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironment
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironment
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironment[] = L"Windows.UI.WindowManagement.IWindowingEnvironment";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("264363C0-2A49-5417-B3AE-48A71C63A3BD"), exclusiveto, contract] */
                MIDL_INTERFACE("264363C0-2A49-5417-B3AE-48A71C63A3BD")
                IWindowingEnvironment : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Kind(
                        /* [retval, out] */__RPC__out ABI::Windows::UI::WindowManagement::WindowingEnvironmentKind * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDisplayRegions(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * * result
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Changed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Changed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWindowingEnvironment=_uuidof(IWindowingEnvironment);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentAddedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironmentAddedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentAddedEventArgs[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentAddedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("FF2A5B7F-F183-5C66-99B2-429082069299"), exclusiveto, contract] */
                MIDL_INTERFACE("FF2A5B7F-F183-5C66-99B2-429082069299")
                IWindowingEnvironmentAddedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WindowingEnvironment(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IWindowingEnvironment * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWindowingEnvironmentAddedEventArgs=_uuidof(IWindowingEnvironmentAddedEventArgs);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentChangedEventArgs[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("4160CFC6-023D-5E9A-B431-350E67DC978A"), exclusiveto, contract] */
                MIDL_INTERFACE("4160CFC6-023D-5E9A-B431-350E67DC978A")
                IWindowingEnvironmentChangedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IWindowingEnvironmentChangedEventArgs=_uuidof(IWindowingEnvironmentChangedEventArgs);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentRemovedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironmentRemovedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentRemovedEventArgs[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentRemovedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("2E5B5473-BEFF-5E53-9316-7E775FE568B3"), exclusiveto, contract] */
                MIDL_INTERFACE("2E5B5473-BEFF-5E53-9316-7E775FE568B3")
                IWindowingEnvironmentRemovedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WindowingEnvironment(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::WindowManagement::IWindowingEnvironment * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWindowingEnvironmentRemovedEventArgs=_uuidof(IWindowingEnvironmentRemovedEventArgs);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironment
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentStatics[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                /* [object, uuid("874E9FB7-C642-55AB-8AA2-162F734A9A72"), exclusiveto, contract] */
                MIDL_INTERFACE("874E9FB7-C642-55AB-8AA2-162F734A9A72")
                IWindowingEnvironmentStatics : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE FindAll(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * * result
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE FindAllWithKind(
                        /* [in] */ABI::Windows::UI::WindowManagement::WindowingEnvironmentKind kind,
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IWindowingEnvironmentStatics=_uuidof(IWindowingEnvironmentStatics);
                
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindow
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.WindowManagement.IAppWindowStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindow ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindow_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindow_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindow[] = L"Windows.UI.WindowManagement.AppWindow";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowChangedEventArgs[] = L"Windows.UI.WindowManagement.AppWindowChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowCloseRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowCloseRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowCloseRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowCloseRequestedEventArgs[] = L"Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowClosedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowClosedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowClosedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowClosedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowClosedEventArgs[] = L"Windows.UI.WindowManagement.AppWindowClosedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowFrameStyle
 *    Windows.UI.WindowManagement.IAppWindowFrame ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowFrame_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowFrame_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowFrame[] = L"Windows.UI.WindowManagement.AppWindowFrame";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowPlacement
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowPlacement ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPlacement_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPlacement_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowPlacement[] = L"Windows.UI.WindowManagement.AppWindowPlacement";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowPresentationConfiguration[] = L"Windows.UI.WindowManagement.AppWindowPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowPresenter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowPresenter ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresenter_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresenter_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowPresenter[] = L"Windows.UI.WindowManagement.AppWindowPresenter";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowTitleBar
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowTitleBarVisibility
 *    Windows.UI.WindowManagement.IAppWindowTitleBar ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBar_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBar_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowTitleBar[] = L"Windows.UI.WindowManagement.AppWindowTitleBar";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowTitleBarOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowTitleBarOcclusion ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBarOcclusion_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBarOcclusion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowTitleBarOcclusion[] = L"Windows.UI.WindowManagement.AppWindowTitleBarOcclusion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.CompactOverlayPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.ICompactOverlayPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_CompactOverlayPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_CompactOverlayPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_CompactOverlayPresentationConfiguration[] = L"Windows.UI.WindowManagement.CompactOverlayPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.DefaultPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IDefaultPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_DefaultPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_DefaultPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_DefaultPresentationConfiguration[] = L"Windows.UI.WindowManagement.DefaultPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.DisplayRegion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IDisplayRegion ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_DisplayRegion_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_DisplayRegion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_DisplayRegion[] = L"Windows.UI.WindowManagement.DisplayRegion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.FullScreenPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IFullScreenPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_FullScreenPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_FullScreenPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_FullScreenPresentationConfiguration[] = L"Windows.UI.WindowManagement.FullScreenPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironment
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.WindowManagement.IWindowingEnvironmentStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironment ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironment_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironment_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironment[] = L"Windows.UI.WindowManagement.WindowingEnvironment";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironmentAddedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironmentAddedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentAddedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentAddedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironmentAddedEventArgs[] = L"Windows.UI.WindowManagement.WindowingEnvironmentAddedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironmentChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironmentChangedEventArgs[] = L"Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironmentRemovedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironmentRemovedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentRemovedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentRemovedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironmentRemovedEventArgs[] = L"Windows.UI.WindowManagement.WindowingEnvironmentRemovedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion;

typedef struct __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl;

interface __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion;

typedef  struct __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl;

interface __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion;

typedef struct __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl;

interface __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion;

typedef  struct __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CWindowManagement__CDisplayRegion **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl;

interface __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment;

typedef struct __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl;

interface __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment;

typedef  struct __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CWindowManagement__CWindowingEnvironment **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl;

interface __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion;

typedef struct __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
            /* [in] */ __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl;

interface __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion;

typedef struct __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
            /* [in] */ __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl;

interface __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment;

typedef struct __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
            /* [in] */ __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl;

interface __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironmentVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindowVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindowVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindowVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow;

typedef struct __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindowVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CUI__CWindowManagement__CAppWindow **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindowVtbl;

interface __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindowVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

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


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVisualElement __x_ABI_CWindows_CUI_CComposition_CIVisualElement;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CIVisualElement __FIIterator_1_Windows__CUI__CComposition__CIVisualElement;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CIVisualElement;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CIVisualElementVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CIVisualElementVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CIVisualElement
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CIVisualElementVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CIVisualElement_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CIVisualElement __FIIterable_1_Windows__CUI__CComposition__CIVisualElement;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CIVisualElement;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CIVisualElementVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CIVisualElement * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CIVisualElement **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CIVisualElementVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CIVisualElement
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CIVisualElementVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CIVisualElement_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CComposition__CIVisualElement;

typedef struct __FIVectorView_1_Windows__CUI__CComposition__CIVisualElementVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
            /* [in] */ __x_ABI_CWindows_CUI_CComposition_CIVisualElement * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CComposition__CIVisualElementVtbl;

interface __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CComposition__CIVisualElementVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVector_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__)
#define ____FIVector_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

typedef interface __FIVector_1_Windows__CUI__CComposition__CIVisualElement __FIVector_1_Windows__CUI__CComposition__CIVisualElement;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_Windows__CUI__CComposition__CIVisualElement;

typedef struct __FIVector_1_Windows__CUI__CComposition__CIVisualElementVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This, /* [out] */ __RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CComposition__CIVisualElement **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CIVisualElement * item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CIVisualElement * item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CIVisualElement * item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This, /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CIVisualElement * item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CIVisualElement * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) __x_ABI_CWindows_CUI_CComposition_CIVisualElement * *value);

    END_INTERFACE
} __FIVector_1_Windows__CUI__CComposition__CIVisualElementVtbl;

interface __FIVector_1_Windows__CUI__CComposition__CIVisualElement
{
    CONST_VTBL struct __FIVector_1_Windows__CUI__CComposition__CIVisualElementVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_Windows__CUI__CComposition__CIVisualElement_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_Windows__CUI__CComposition__CIVisualElement_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

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



#ifndef ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIDeferral __x_ABI_CWindows_CFoundation_CIDeferral;

#endif // ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIAsyncAction __x_ABI_CWindows_CFoundation_CIAsyncAction;

#endif // ____x_ABI_CWindows_CFoundation_CIAsyncAction_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CPoint __x_ABI_CWindows_CFoundation_CPoint;


typedef struct __x_ABI_CWindows_CFoundation_CRect __x_ABI_CWindows_CFoundation_CRect;


typedef struct __x_ABI_CWindows_CFoundation_CSize __x_ABI_CWindows_CFoundation_CSize;




#ifndef ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CIDispatcherQueue __x_ABI_CWindows_CSystem_CIDispatcherQueue;

#endif // ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__





typedef struct __x_ABI_CWindows_CUI_CColor __x_ABI_CWindows_CUI_CColor;







#ifndef ____x_ABI_CWindows_CUI_CIUIContentRoot_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CIUIContentRoot_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CIUIContentRoot __x_ABI_CWindows_CUI_CIUIContentRoot;

#endif // ____x_ABI_CWindows_CUI_CIUIContentRoot_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CIUIContext __x_ABI_CWindows_CUI_CIUIContext;

#endif // ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__





typedef enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowClosedReason __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowClosedReason;


typedef enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowFrameStyle __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowFrameStyle;


typedef enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowPresentationKind __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowPresentationKind;


typedef enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowTitleBarVisibility __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowTitleBarVisibility;


typedef enum __x_ABI_CWindows_CUI_CWindowManagement_CWindowingEnvironmentKind __x_ABI_CWindows_CUI_CWindowManagement_CWindowingEnvironmentKind;


















































/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowClosedReason
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowClosedReason
{
    AppWindowClosedReason_Other = 0,
    AppWindowClosedReason_AppInitiated = 1,
    AppWindowClosedReason_UserInitiated = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowFrameStyle
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowFrameStyle
{
    AppWindowFrameStyle_Default = 0,
    AppWindowFrameStyle_NoFrame = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowPresentationKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowPresentationKind
{
    AppWindowPresentationKind_Default = 0,
    AppWindowPresentationKind_CompactOverlay = 1,
    AppWindowPresentationKind_FullScreen = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.AppWindowTitleBarVisibility
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowTitleBarVisibility
{
    AppWindowTitleBarVisibility_Default = 0,
    AppWindowTitleBarVisibility_AlwaysHidden = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.WindowManagement.WindowingEnvironmentKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CWindowManagement_CWindowingEnvironmentKind
{
    WindowingEnvironmentKind_Unknown = 0,
    WindowingEnvironmentKind_Overlapped = 1,
    WindowingEnvironmentKind_Tiled = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindow
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindow
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindow[] = L"Windows.UI.WindowManagement.IAppWindow";
/* [object, uuid("663014A6-B75E-5DBD-995C-F0117FA3FB61"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Content )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CIUIContentRoot * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DispatcherQueue )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSystem_CIDispatcherQueue * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Frame )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVisible )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PersistedStateId )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PersistedStateId )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Presenter )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Title )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Title )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TitleBar )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UIContext )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CIUIContext * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WindowingEnvironment )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * * value
        );
    HRESULT ( STDMETHODCALLTYPE *CloseAsync )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetPlacement )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetDisplayRegions )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * * result
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMoveToDisplayRegion )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * displayRegion
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMoveAdjacentToCurrentView )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMoveAdjacentToWindow )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * anchorWindow
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMoveRelativeToWindowContent )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * anchorWindow,
        /* [in] */__x_ABI_CWindows_CFoundation_CPoint contentOffset
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMoveRelativeToCurrentViewContent )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CPoint contentOffset
        );
    HRESULT ( STDMETHODCALLTYPE *RequestMoveRelativeToDisplayRegion )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * displayRegion,
        /* [in] */__x_ABI_CWindows_CFoundation_CPoint displayRegionOffset
        );
    HRESULT ( STDMETHODCALLTYPE *RequestSize )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CSize frameSize
        );
    HRESULT ( STDMETHODCALLTYPE *TryShowAsync )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Changed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Changed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Closed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowClosedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Closed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_CloseRequested )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CAppWindow_Windows__CUI__CWindowManagement__CAppWindowCloseRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_CloseRequested )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_Content(This,value) \
    ( (This)->lpVtbl->get_Content(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_DispatcherQueue(This,value) \
    ( (This)->lpVtbl->get_DispatcherQueue(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_Frame(This,value) \
    ( (This)->lpVtbl->get_Frame(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_IsVisible(This,value) \
    ( (This)->lpVtbl->get_IsVisible(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_PersistedStateId(This,value) \
    ( (This)->lpVtbl->get_PersistedStateId(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_put_PersistedStateId(This,value) \
    ( (This)->lpVtbl->put_PersistedStateId(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_Presenter(This,value) \
    ( (This)->lpVtbl->get_Presenter(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_Title(This,value) \
    ( (This)->lpVtbl->get_Title(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_put_Title(This,value) \
    ( (This)->lpVtbl->put_Title(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_TitleBar(This,value) \
    ( (This)->lpVtbl->get_TitleBar(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_UIContext(This,value) \
    ( (This)->lpVtbl->get_UIContext(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_get_WindowingEnvironment(This,value) \
    ( (This)->lpVtbl->get_WindowingEnvironment(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_CloseAsync(This,operation) \
    ( (This)->lpVtbl->CloseAsync(This,operation) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_GetPlacement(This,result) \
    ( (This)->lpVtbl->GetPlacement(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_GetDisplayRegions(This,result) \
    ( (This)->lpVtbl->GetDisplayRegions(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestMoveToDisplayRegion(This,displayRegion) \
    ( (This)->lpVtbl->RequestMoveToDisplayRegion(This,displayRegion) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestMoveAdjacentToCurrentView(This) \
    ( (This)->lpVtbl->RequestMoveAdjacentToCurrentView(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestMoveAdjacentToWindow(This,anchorWindow) \
    ( (This)->lpVtbl->RequestMoveAdjacentToWindow(This,anchorWindow) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestMoveRelativeToWindowContent(This,anchorWindow,contentOffset) \
    ( (This)->lpVtbl->RequestMoveRelativeToWindowContent(This,anchorWindow,contentOffset) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestMoveRelativeToCurrentViewContent(This,contentOffset) \
    ( (This)->lpVtbl->RequestMoveRelativeToCurrentViewContent(This,contentOffset) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestMoveRelativeToDisplayRegion(This,displayRegion,displayRegionOffset) \
    ( (This)->lpVtbl->RequestMoveRelativeToDisplayRegion(This,displayRegion,displayRegionOffset) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_RequestSize(This,frameSize) \
    ( (This)->lpVtbl->RequestSize(This,frameSize) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_TryShowAsync(This,operation) \
    ( (This)->lpVtbl->TryShowAsync(This,operation) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_add_Changed(This,handler,token) \
    ( (This)->lpVtbl->add_Changed(This,handler,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_remove_Changed(This,token) \
    ( (This)->lpVtbl->remove_Changed(This,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_add_Closed(This,handler,token) \
    ( (This)->lpVtbl->add_Closed(This,handler,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_remove_Closed(This,token) \
    ( (This)->lpVtbl->remove_Closed(This,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_add_CloseRequested(This,handler,token) \
    ( (This)->lpVtbl->add_CloseRequested(This,handler,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_remove_CloseRequested(This,token) \
    ( (This)->lpVtbl->remove_CloseRequested(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowChangedEventArgs[] = L"Windows.UI.WindowManagement.IAppWindowChangedEventArgs";
/* [object, uuid("1DE1F3BE-A655-55AD-B2B6-EB240F880356"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidAvailableWindowPresentationsChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidDisplayRegionsChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidFrameChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidSizeChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidTitleBarChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidVisibilityChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidWindowingEnvironmentChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DidWindowPresentationChange )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidAvailableWindowPresentationsChange(This,value) \
    ( (This)->lpVtbl->get_DidAvailableWindowPresentationsChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidDisplayRegionsChange(This,value) \
    ( (This)->lpVtbl->get_DidDisplayRegionsChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidFrameChange(This,value) \
    ( (This)->lpVtbl->get_DidFrameChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidSizeChange(This,value) \
    ( (This)->lpVtbl->get_DidSizeChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidTitleBarChange(This,value) \
    ( (This)->lpVtbl->get_DidTitleBarChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidVisibilityChange(This,value) \
    ( (This)->lpVtbl->get_DidVisibilityChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidWindowingEnvironmentChange(This,value) \
    ( (This)->lpVtbl->get_DidWindowingEnvironmentChange(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_get_DidWindowPresentationChange(This,value) \
    ( (This)->lpVtbl->get_DidWindowPresentationChange(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowCloseRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs[] = L"Windows.UI.WindowManagement.IAppWindowCloseRequestedEventArgs";
/* [object, uuid("E9FF01DA-E7A2-57A8-8B5E-39C4003AFDBB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Cancel )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Cancel )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
        /* [in] */boolean value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_get_Cancel(This,value) \
    ( (This)->lpVtbl->get_Cancel(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_put_Cancel(This,value) \
    ( (This)->lpVtbl->put_Cancel(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_GetDeferral(This,result) \
    ( (This)->lpVtbl->GetDeferral(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowCloseRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowClosedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowClosedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowClosedEventArgs[] = L"Windows.UI.WindowManagement.IAppWindowClosedEventArgs";
/* [object, uuid("CC7DF816-9520-5A06-821E-456AD8B358AA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Reason )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowClosedReason * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_get_Reason(This,value) \
    ( (This)->lpVtbl->get_Reason(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowClosedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowFrame
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowFrame[] = L"Windows.UI.WindowManagement.IAppWindowFrame";
/* [object, uuid("9EE22601-7E5D-52AF-846B-01DC6C296567"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DragRegionVisuals )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CUI__CComposition__CIVisualElement * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_get_DragRegionVisuals(This,value) \
    ( (This)->lpVtbl->get_DragRegionVisuals(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrame_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowFrameStyle
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowFrame
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowFrameStyle[] = L"Windows.UI.WindowManagement.IAppWindowFrameStyle";
/* [object, uuid("AC412946-E1AC-5230-944A-C60873DCF4A9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyleVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetFrameStyle )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowFrameStyle * result
        );
    HRESULT ( STDMETHODCALLTYPE *SetFrameStyle )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle * This,
        /* [in] */__x_ABI_CWindows_CUI_CWindowManagement_CAppWindowFrameStyle frameStyle
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyleVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyleVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_GetFrameStyle(This,result) \
    ( (This)->lpVtbl->GetFrameStyle(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_SetFrameStyle(This,frameStyle) \
    ( (This)->lpVtbl->SetFrameStyle(This,frameStyle) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowFrameStyle_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPlacement
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPlacement
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPlacement[] = L"Windows.UI.WindowManagement.IAppWindowPlacement";
/* [object, uuid("03DC815E-E7A9-5857-9C03-7D670594410E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacementVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayRegion )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Offset )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Size )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CSize * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacementVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacementVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_get_DisplayRegion(This,value) \
    ( (This)->lpVtbl->get_DisplayRegion(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_get_Offset(This,value) \
    ( (This)->lpVtbl->get_Offset(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_get_Size(This,value) \
    ( (This)->lpVtbl->get_Size(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPlacement_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPresentationConfiguration[] = L"Windows.UI.WindowManagement.IAppWindowPresentationConfiguration";
/* [object, uuid("B5A43EE3-DF33-5E67-BD31-1072457300DF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Kind )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowPresentationKind * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_get_Kind(This,value) \
    ( (This)->lpVtbl->get_Kind(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPresentationConfigurationFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPresentationConfigurationFactory[] = L"Windows.UI.WindowManagement.IAppWindowPresentationConfigurationFactory";
/* [object, uuid("FD3606A6-7875-5DE8-84FF-6351EE13DD0D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactoryVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfigurationFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowPresenter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowPresenter
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowPresenter[] = L"Windows.UI.WindowManagement.IAppWindowPresenter";
/* [object, uuid("5AE9ED73-E1FD-5317-AD78-5A3ED271BBDE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenterVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetConfiguration )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * * result
        );
    HRESULT ( STDMETHODCALLTYPE *IsPresentationSupported )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
        /* [in] */__x_ABI_CWindows_CUI_CWindowManagement_CAppWindowPresentationKind presentationKind,
        /* [retval, out] */__RPC__out boolean * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *RequestPresentation )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresentationConfiguration * configuration,
        /* [retval, out] */__RPC__out boolean * result
        );
    /* [overload, default_overload] */HRESULT ( STDMETHODCALLTYPE *RequestPresentationByKind )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter * This,
        /* [in] */__x_ABI_CWindows_CUI_CWindowManagement_CAppWindowPresentationKind presentationKind,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenterVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenterVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_GetConfiguration(This,result) \
    ( (This)->lpVtbl->GetConfiguration(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_IsPresentationSupported(This,presentationKind,result) \
    ( (This)->lpVtbl->IsPresentationSupported(This,presentationKind,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_RequestPresentation(This,configuration,result) \
    ( (This)->lpVtbl->RequestPresentation(This,configuration,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_RequestPresentationByKind(This,presentationKind,result) \
    ( (This)->lpVtbl->RequestPresentationByKind(This,presentationKind,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowPresenter_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindow
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowStatics[] = L"Windows.UI.WindowManagement.IAppWindowStatics";
/* [object, uuid("FF1F3EA3-B769-50EF-9873-108CD0E89746"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *TryCreateAsync )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CUI__CWindowManagement__CAppWindow * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *ClearAllPersistedState )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This
        );
    HRESULT ( STDMETHODCALLTYPE *ClearPersistedState )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics * This,
        /* [in] */__RPC__in HSTRING key
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStaticsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_TryCreateAsync(This,operation) \
    ( (This)->lpVtbl->TryCreateAsync(This,operation) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_ClearAllPersistedState(This) \
    ( (This)->lpVtbl->ClearAllPersistedState(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_ClearPersistedState(This,key) \
    ( (This)->lpVtbl->ClearPersistedState(This,key) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowTitleBar
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowTitleBar
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowTitleBar[] = L"Windows.UI.WindowManagement.IAppWindowTitleBar";
/* [object, uuid("6E932C84-F644-541D-A2D7-0C262437842D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonHoverBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonHoverBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonHoverForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonHoverForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonInactiveBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonInactiveBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonInactiveForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonInactiveForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonPressedBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonPressedBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ButtonPressedForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ButtonPressedForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendsContentIntoTitleBar )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ExtendsContentIntoTitleBar )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InactiveBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_InactiveBackgroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InactiveForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CUI__CColor * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_InactiveForegroundColor )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CUI__CColor * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVisible )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetTitleBarOcclusions )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CAppWindowTitleBarOcclusion * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_BackgroundColor(This,value) \
    ( (This)->lpVtbl->get_BackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_BackgroundColor(This,value) \
    ( (This)->lpVtbl->put_BackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonBackgroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonBackgroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonForegroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonForegroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonHoverBackgroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonHoverBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonHoverBackgroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonHoverBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonHoverForegroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonHoverForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonHoverForegroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonHoverForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonInactiveBackgroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonInactiveBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonInactiveBackgroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonInactiveBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonInactiveForegroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonInactiveForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonInactiveForegroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonInactiveForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonPressedBackgroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonPressedBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonPressedBackgroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonPressedBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ButtonPressedForegroundColor(This,value) \
    ( (This)->lpVtbl->get_ButtonPressedForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ButtonPressedForegroundColor(This,value) \
    ( (This)->lpVtbl->put_ButtonPressedForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ExtendsContentIntoTitleBar(This,value) \
    ( (This)->lpVtbl->get_ExtendsContentIntoTitleBar(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ExtendsContentIntoTitleBar(This,value) \
    ( (This)->lpVtbl->put_ExtendsContentIntoTitleBar(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_ForegroundColor(This,value) \
    ( (This)->lpVtbl->get_ForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_ForegroundColor(This,value) \
    ( (This)->lpVtbl->put_ForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_InactiveBackgroundColor(This,value) \
    ( (This)->lpVtbl->get_InactiveBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_InactiveBackgroundColor(This,value) \
    ( (This)->lpVtbl->put_InactiveBackgroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_InactiveForegroundColor(This,value) \
    ( (This)->lpVtbl->get_InactiveForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_put_InactiveForegroundColor(This,value) \
    ( (This)->lpVtbl->put_InactiveForegroundColor(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_get_IsVisible(This,value) \
    ( (This)->lpVtbl->get_IsVisible(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_GetTitleBarOcclusions(This,result) \
    ( (This)->lpVtbl->GetTitleBarOcclusions(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBar_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowTitleBarOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowTitleBarOcclusion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowTitleBarOcclusion[] = L"Windows.UI.WindowManagement.IAppWindowTitleBarOcclusion";
/* [object, uuid("FEA3CFFD-2CCF-5FC3-AEAE-F843876BF37E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OccludingRect )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CRect * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusionVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_get_OccludingRect(This,value) \
    ( (This)->lpVtbl->get_OccludingRect(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarOcclusion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IAppWindowTitleBarVisibility
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.AppWindowTitleBar
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IAppWindowTitleBarVisibility[] = L"Windows.UI.WindowManagement.IAppWindowTitleBarVisibility";
/* [object, uuid("A215A4E3-6E7E-5651-8C3B-624819528154"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibilityVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetPreferredVisibility )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CAppWindowTitleBarVisibility * result
        );
    HRESULT ( STDMETHODCALLTYPE *SetPreferredVisibility )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility * This,
        /* [in] */__x_ABI_CWindows_CUI_CWindowManagement_CAppWindowTitleBarVisibility visibilityMode
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibilityVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibilityVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_GetPreferredVisibility(This,result) \
    ( (This)->lpVtbl->GetPreferredVisibility(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_SetPreferredVisibility(This,visibilityMode) \
    ( (This)->lpVtbl->SetPreferredVisibility(This,visibilityMode) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindowTitleBarVisibility_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.ICompactOverlayPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.CompactOverlayPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_ICompactOverlayPresentationConfiguration[] = L"Windows.UI.WindowManagement.ICompactOverlayPresentationConfiguration";
/* [object, uuid("A7E5750F-5730-56C6-8E1F-D63FF4D7980D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfigurationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfigurationVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfigurationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CICompactOverlayPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IDefaultPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.DefaultPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IDefaultPresentationConfiguration[] = L"Windows.UI.WindowManagement.IDefaultPresentationConfiguration";
/* [object, uuid("D8C2B53B-2168-5703-A853-D525589FE2B9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfigurationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfigurationVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfigurationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDefaultPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IDisplayRegion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.DisplayRegion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IDisplayRegion[] = L"Windows.UI.WindowManagement.IDisplayRegion";
/* [object, uuid("DB50C3A2-4094-5F47-8CB1-EA01DDAFAA94"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayMonitorDeviceId )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVisible )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WorkAreaOffset )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WorkAreaSize )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CSize * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WindowingEnvironment )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Changed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CDisplayRegion_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Changed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegionVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_get_DisplayMonitorDeviceId(This,value) \
    ( (This)->lpVtbl->get_DisplayMonitorDeviceId(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_get_IsVisible(This,value) \
    ( (This)->lpVtbl->get_IsVisible(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_get_WorkAreaOffset(This,value) \
    ( (This)->lpVtbl->get_WorkAreaOffset(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_get_WorkAreaSize(This,value) \
    ( (This)->lpVtbl->get_WorkAreaSize(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_get_WindowingEnvironment(This,value) \
    ( (This)->lpVtbl->get_WindowingEnvironment(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_add_Changed(This,handler,token) \
    ( (This)->lpVtbl->add_Changed(This,handler,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_remove_Changed(This,token) \
    ( (This)->lpVtbl->remove_Changed(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIDisplayRegion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IFullScreenPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.FullScreenPresentationConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IFullScreenPresentationConfiguration[] = L"Windows.UI.WindowManagement.IFullScreenPresentationConfiguration";
/* [object, uuid("43D3DCD8-D2A8-503D-A626-15533D6D5F62"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfigurationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsExclusive )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsExclusive )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfigurationVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfigurationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_get_IsExclusive(This,value) \
    ( (This)->lpVtbl->get_IsExclusive(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_put_IsExclusive(This,value) \
    ( (This)->lpVtbl->put_IsExclusive(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIFullScreenPresentationConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironment
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironment
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironment[] = L"Windows.UI.WindowManagement.IWindowingEnvironment";
/* [object, uuid("264363C0-2A49-5417-B3AE-48A71C63A3BD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsEnabled )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Kind )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CWindowManagement_CWindowingEnvironmentKind * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDisplayRegions )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CDisplayRegion * * result
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Changed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CWindowManagement__CWindowingEnvironment_Windows__CUI__CWindowManagement__CWindowingEnvironmentChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Changed )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_get_IsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsEnabled(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_get_Kind(This,value) \
    ( (This)->lpVtbl->get_Kind(This,value) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_GetDisplayRegions(This,result) \
    ( (This)->lpVtbl->GetDisplayRegions(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_add_Changed(This,handler,token) \
    ( (This)->lpVtbl->add_Changed(This,handler,token) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_remove_Changed(This,token) \
    ( (This)->lpVtbl->remove_Changed(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentAddedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironmentAddedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentAddedEventArgs[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentAddedEventArgs";
/* [object, uuid("FF2A5B7F-F183-5C66-99B2-429082069299"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WindowingEnvironment )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_get_WindowingEnvironment(This,value) \
    ( (This)->lpVtbl->get_WindowingEnvironment(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentAddedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentChangedEventArgs[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentChangedEventArgs";
/* [object, uuid("4160CFC6-023D-5E9A-B431-350E67DC978A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentRemovedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironmentRemovedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentRemovedEventArgs[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentRemovedEventArgs";
/* [object, uuid("2E5B5473-BEFF-5E53-9316-7E775FE568B3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WindowingEnvironment )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironment * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_get_WindowingEnvironment(This,value) \
    ( (This)->lpVtbl->get_WindowingEnvironment(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentRemovedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.WindowManagement.IWindowingEnvironmentStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.WindowManagement.WindowingEnvironment
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_WindowManagement_IWindowingEnvironmentStatics[] = L"Windows.UI.WindowManagement.IWindowingEnvironmentStatics";
/* [object, uuid("874E9FB7-C642-55AB-8AA2-162F734A9A72"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *FindAll )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *FindAllWithKind )(
        __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics * This,
        /* [in] */__x_ABI_CWindows_CUI_CWindowManagement_CWindowingEnvironmentKind kind,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CWindowManagement__CWindowingEnvironment * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStaticsVtbl;

interface __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FindAll(This,result) \
    ( (This)->lpVtbl->FindAll(This,result) )

#define __x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_FindAllWithKind(This,kind,result) \
    ( (This)->lpVtbl->FindAllWithKind(This,kind,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CWindowManagement_CIWindowingEnvironmentStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindow
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.WindowManagement.IAppWindowStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindow ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindow_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindow_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindow[] = L"Windows.UI.WindowManagement.AppWindow";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowChangedEventArgs[] = L"Windows.UI.WindowManagement.AppWindowChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowCloseRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowCloseRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowCloseRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowCloseRequestedEventArgs[] = L"Windows.UI.WindowManagement.AppWindowCloseRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowClosedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowClosedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowClosedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowClosedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowClosedEventArgs[] = L"Windows.UI.WindowManagement.AppWindowClosedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowFrameStyle
 *    Windows.UI.WindowManagement.IAppWindowFrame ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowFrame_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowFrame_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowFrame[] = L"Windows.UI.WindowManagement.AppWindowFrame";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowPlacement
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowPlacement ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPlacement_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPlacement_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowPlacement[] = L"Windows.UI.WindowManagement.AppWindowPlacement";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowPresentationConfiguration[] = L"Windows.UI.WindowManagement.AppWindowPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowPresenter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowPresenter ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresenter_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowPresenter_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowPresenter[] = L"Windows.UI.WindowManagement.AppWindowPresenter";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowTitleBar
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowTitleBarVisibility
 *    Windows.UI.WindowManagement.IAppWindowTitleBar ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBar_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBar_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowTitleBar[] = L"Windows.UI.WindowManagement.AppWindowTitleBar";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.AppWindowTitleBarOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IAppWindowTitleBarOcclusion ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBarOcclusion_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_AppWindowTitleBarOcclusion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_AppWindowTitleBarOcclusion[] = L"Windows.UI.WindowManagement.AppWindowTitleBarOcclusion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.CompactOverlayPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.ICompactOverlayPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_CompactOverlayPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_CompactOverlayPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_CompactOverlayPresentationConfiguration[] = L"Windows.UI.WindowManagement.CompactOverlayPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.DefaultPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IDefaultPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_DefaultPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_DefaultPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_DefaultPresentationConfiguration[] = L"Windows.UI.WindowManagement.DefaultPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.DisplayRegion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IDisplayRegion ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_DisplayRegion_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_DisplayRegion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_DisplayRegion[] = L"Windows.UI.WindowManagement.DisplayRegion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.FullScreenPresentationConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IFullScreenPresentationConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_FullScreenPresentationConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_FullScreenPresentationConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_FullScreenPresentationConfiguration[] = L"Windows.UI.WindowManagement.FullScreenPresentationConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironment
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.WindowManagement.IWindowingEnvironmentStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironment ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironment_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironment_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironment[] = L"Windows.UI.WindowManagement.WindowingEnvironment";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironmentAddedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironmentAddedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentAddedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentAddedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironmentAddedEventArgs[] = L"Windows.UI.WindowManagement.WindowingEnvironmentAddedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironmentChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironmentChangedEventArgs[] = L"Windows.UI.WindowManagement.WindowingEnvironmentChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.WindowManagement.WindowingEnvironmentRemovedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.WindowManagement.IWindowingEnvironmentRemovedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentRemovedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_WindowManagement_WindowingEnvironmentRemovedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_WindowManagement_WindowingEnvironmentRemovedEventArgs[] = L"Windows.UI.WindowManagement.WindowingEnvironmentRemovedEventArgs";
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
#endif // __windows2Eui2Ewindowmanagement_p_h__

#endif // __windows2Eui2Ewindowmanagement_h__
