/* Header file automatically generated from windows.graphics.display.idl */
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
#ifndef __windows2Egraphics2Edisplay_h__
#define __windows2Egraphics2Edisplay_h__
#ifndef __windows2Egraphics2Edisplay_p_h__
#define __windows2Egraphics2Edisplay_p_h__


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
#include "Windows.Storage.Streams.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayPropertiesEventHandler;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler ABI::Windows::Graphics::Display::IDisplayPropertiesEventHandler

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IAdvancedColorInfo;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo ABI::Windows::Graphics::Display::IAdvancedColorInfo

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IBrightnessOverride;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride ABI::Windows::Graphics::Display::IBrightnessOverride

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IBrightnessOverrideSettings;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings ABI::Windows::Graphics::Display::IBrightnessOverrideSettings

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IBrightnessOverrideSettingsStatics;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics ABI::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IBrightnessOverrideStatics;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics ABI::Windows::Graphics::Display::IBrightnessOverrideStatics

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IColorOverrideSettings;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings ABI::Windows::Graphics::Display::IColorOverrideSettings

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IColorOverrideSettingsStatics;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics ABI::Windows::Graphics::Display::IColorOverrideSettingsStatics

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayEnhancementOverride;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride ABI::Windows::Graphics::Display::IDisplayEnhancementOverride

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayEnhancementOverrideCapabilities;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayEnhancementOverrideCapabilitiesChangedEventArgs;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayEnhancementOverrideStatics;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayInformation;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation ABI::Windows::Graphics::Display::IDisplayInformation

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayInformation2;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 ABI::Windows::Graphics::Display::IDisplayInformation2

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayInformation3;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 ABI::Windows::Graphics::Display::IDisplayInformation3

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayInformation4;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 ABI::Windows::Graphics::Display::IDisplayInformation4

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayInformation5;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 ABI::Windows::Graphics::Display::IDisplayInformation5

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayInformationStatics;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics ABI::Windows::Graphics::Display::IDisplayInformationStatics

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                interface IDisplayPropertiesStatics;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics ABI::Windows::Graphics::Display::IDisplayPropertiesStatics

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                struct NitRange;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */


#ifndef DEF___FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_USE
#define DEF___FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6be92993-d069-5a99-b9e8-200cf5c8a060"))
IIterator<struct ABI::Windows::Graphics::Display::NitRange> : IIterator_impl<struct ABI::Windows::Graphics::Display::NitRange> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Graphics.Display.NitRange>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<struct ABI::Windows::Graphics::Display::NitRange> __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_t;
#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Graphics::Display::NitRange>
//#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Graphics::Display::NitRange>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_USE */





#ifndef DEF___FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_USE
#define DEF___FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7fb7a783-ce2d-552d-bee3-bc1442db0409"))
IIterable<struct ABI::Windows::Graphics::Display::NitRange> : IIterable_impl<struct ABI::Windows::Graphics::Display::NitRange> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Graphics.Display.NitRange>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<struct ABI::Windows::Graphics::Display::NitRange> __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_t;
#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Graphics::Display::NitRange>
//#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Graphics::Display::NitRange>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_USE */





#ifndef DEF___FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_USE
#define DEF___FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("cc8ef226-50c1-5efa-98c4-1043d0bf5b35"))
IVectorView<struct ABI::Windows::Graphics::Display::NitRange> : IVectorView_impl<struct ABI::Windows::Graphics::Display::NitRange> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Graphics.Display.NitRange>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<struct ABI::Windows::Graphics::Display::NitRange> __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_t;
#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Graphics::Display::NitRange>
//#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Graphics::Display::NitRange>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_USE */



namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class BrightnessOverride;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("a460214e-6620-521d-9cb9-a0a0f732ce90"))
ITypedEventHandler<ABI::Windows::Graphics::Display::BrightnessOverride*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Display::BrightnessOverride*, ABI::Windows::Graphics::Display::IBrightnessOverride*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Graphics.Display.BrightnessOverride, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Graphics::Display::BrightnessOverride*,IInspectable*> __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IBrightnessOverride*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IBrightnessOverride*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class DisplayEnhancementOverride;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3247b54b-7f00-5555-81df-afae022f0796"))
ITypedEventHandler<ABI::Windows::Graphics::Display::DisplayEnhancementOverride*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Display::DisplayEnhancementOverride*, ABI::Windows::Graphics::Display::IDisplayEnhancementOverride*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Graphics.Display.DisplayEnhancementOverride, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Graphics::Display::DisplayEnhancementOverride*,IInspectable*> __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IDisplayEnhancementOverride*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IDisplayEnhancementOverride*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class DisplayEnhancementOverrideCapabilitiesChangedEventArgs;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7e61af14-3e29-5039-92ee-3f2472b99e43"))
ITypedEventHandler<ABI::Windows::Graphics::Display::DisplayEnhancementOverride*,ABI::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Display::DisplayEnhancementOverride*, ABI::Windows::Graphics::Display::IDisplayEnhancementOverride*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs*, ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Graphics.Display.DisplayEnhancementOverride, Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Graphics::Display::DisplayEnhancementOverride*,ABI::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs*> __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IDisplayEnhancementOverride*,ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IDisplayEnhancementOverride*,ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class DisplayInformation;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("86c4f619-67b6-51c7-b30d-d8cf13625327"))
ITypedEventHandler<ABI::Windows::Graphics::Display::DisplayInformation*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Display::DisplayInformation*, ABI::Windows::Graphics::Display::IDisplayInformation*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Graphics.Display.DisplayInformation, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Graphics::Display::DisplayInformation*,IInspectable*> __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IDisplayInformation*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Display::IDisplayInformation*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


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


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("398c4183-793d-5b00-819b-4aef92485e94"))
IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IRandomAccessStream*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Storage::Streams::IRandomAccessStream*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Storage.Streams.IRandomAccessStream>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IRandomAccessStream*> __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IRandomAccessStream*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Storage::Streams::IRandomAccessStream*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_USE
#define DEF___FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("430ecece-1418-5d19-81b2-5ddb381603cc"))
IAsyncOperation<ABI::Windows::Storage::Streams::IRandomAccessStream*> : IAsyncOperation_impl<ABI::Windows::Storage::Streams::IRandomAccessStream*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Storage.Streams.IRandomAccessStream>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Storage::Streams::IRandomAccessStream*> __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_t;
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Storage::Streams::IRandomAccessStream*>
//#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Storage::Streams::IRandomAccessStream*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#ifndef DEF___FIReference_1_double_USE
#define DEF___FIReference_1_double_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2f2d6c29-5473-5f3e-92e7-96572bb990e2"))
IReference<double> : IReference_impl<double> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Double>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<double> __FIReference_1_double_t;
#define __FIReference_1_double ABI::Windows::Foundation::__FIReference_1_double_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_double ABI::Windows::Foundation::IReference<DOUBLE>
//#define __FIReference_1_double_t ABI::Windows::Foundation::IReference<DOUBLE>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_double_USE */





namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Point Point;
            
        } /* Foundation */
    } /* Windows */} /* ABI */








namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum AdvancedColorKind : int AdvancedColorKind;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum DisplayBrightnessOverrideOptions : unsigned int DisplayBrightnessOverrideOptions;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum DisplayBrightnessOverrideScenario : int DisplayBrightnessOverrideScenario;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum DisplayBrightnessScenario : int DisplayBrightnessScenario;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum DisplayColorOverrideScenario : int DisplayColorOverrideScenario;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum DisplayOrientations : unsigned int DisplayOrientations;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum HdrMetadataFormat : int HdrMetadataFormat;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef enum ResolutionScale : int ResolutionScale;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                
                typedef struct NitRange NitRange;
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */




















namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class AdvancedColorInfo;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class BrightnessOverrideSettings;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class ColorOverrideSettings;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                class DisplayEnhancementOverrideCapabilities;
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */













/*
 *
 * Struct Windows.Graphics.Display.AdvancedColorKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, contract] */
                enum AdvancedColorKind : int
                {
                    AdvancedColorKind_StandardDynamicRange = 0,
                    AdvancedColorKind_WideColorGamut = 1,
                    AdvancedColorKind_HighDynamicRange = 2,
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.DisplayBrightnessOverrideOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, flags, contract] */
                enum DisplayBrightnessOverrideOptions : unsigned int
                {
                    DisplayBrightnessOverrideOptions_None = 0,
                    DisplayBrightnessOverrideOptions_UseDimmedPolicyWhenBatteryIsLow = 0x1,
                };
                
                DEFINE_ENUM_FLAG_OPERATORS(DisplayBrightnessOverrideOptions)
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.Display.DisplayBrightnessOverrideScenario
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayBrightnessOverrideScenario : int
                {
                    DisplayBrightnessOverrideScenario_IdleBrightness = 0,
                    DisplayBrightnessOverrideScenario_BarcodeReadingBrightness = 1,
                    DisplayBrightnessOverrideScenario_FullBrightness = 2,
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.DisplayBrightnessScenario
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayBrightnessScenario : int
                {
                    DisplayBrightnessScenario_DefaultBrightness = 0,
                    DisplayBrightnessScenario_IdleBrightness = 1,
                    DisplayBrightnessScenario_BarcodeReadingBrightness = 2,
                    DisplayBrightnessScenario_FullBrightness = 3,
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.Display.DisplayColorOverrideScenario
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayColorOverrideScenario : int
                {
                    DisplayColorOverrideScenario_Accurate = 0,
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.DisplayOrientations
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, flags, contract] */
                enum DisplayOrientations : unsigned int
                {
                    DisplayOrientations_None = 0,
                    DisplayOrientations_Landscape = 0x1,
                    DisplayOrientations_Portrait = 0x2,
                    DisplayOrientations_LandscapeFlipped = 0x4,
                    DisplayOrientations_PortraitFlipped = 0x8,
                };
                
                DEFINE_ENUM_FLAG_OPERATORS(DisplayOrientations)
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Graphics.Display.HdrMetadataFormat
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, contract] */
                enum HdrMetadataFormat : int
                {
                    HdrMetadataFormat_Hdr10 = 0,
                    HdrMetadataFormat_Hdr10Plus = 1,
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.ResolutionScale
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [v1_enum, contract] */
                enum ResolutionScale : int
                {
                    ResolutionScale_Invalid = 0,
                    ResolutionScale_Scale100Percent = 100,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale120Percent = 120,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale125Percent = 125,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale140Percent = 140,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale150Percent = 150,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale160Percent = 160,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale175Percent = 175,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale180Percent = 180,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale200Percent = 200,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale225Percent = 225,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale250Percent = 250,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale300Percent = 300,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale350Percent = 350,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale400Percent = 400,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale450Percent = 450,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                    ResolutionScale_Scale500Percent = 500,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Graphics.Display.NitRange
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [contract] */
                struct NitRange
                {
                    FLOAT MinNits;
                    FLOAT MaxNits;
                    FLOAT StepSizeNits;
                };
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Delegate Windows.Graphics.Display.DisplayPropertiesEventHandler
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_INTERFACE_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("DBDD8B01-F1A1-46D1-9EE3-543BCC995980"), deprecated, contract] */
                MIDL_INTERFACE("DBDD8B01-F1A1-46D1-9EE3-543BCC995980")
                
                #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                IDisplayPropertiesEventHandler : public IUnknown
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Invoke(
                        /* [in] */__RPC__in_opt IInspectable * sender
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayPropertiesEventHandler=_uuidof(IDisplayPropertiesEventHandler);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IAdvancedColorInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.AdvancedColorInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IAdvancedColorInfo[] = L"Windows.Graphics.Display.IAdvancedColorInfo";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("8797DCFB-B229-4081-AE9A-2CC85E34AD6A"), exclusiveto, contract] */
                MIDL_INTERFACE("8797DCFB-B229-4081-AE9A-2CC85E34AD6A")
                IAdvancedColorInfo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CurrentAdvancedColorKind(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::AdvancedColorKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RedPrimary(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_GreenPrimary(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BluePrimary(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WhitePoint(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxLuminanceInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MinLuminanceInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxAverageFullFrameLuminanceInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SdrWhiteLevelInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE IsHdrMetadataFormatCurrentlySupported(
                        /* [in] */ABI::Windows::Graphics::Display::HdrMetadataFormat format,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE IsAdvancedColorKindAvailable(
                        /* [in] */ABI::Windows::Graphics::Display::AdvancedColorKind kind,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IAdvancedColorInfo=_uuidof(IAdvancedColorInfo);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverride[] = L"Windows.Graphics.Display.IBrightnessOverride";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("96C9621A-C143-4392-BEDD-4A7E9574C8FD"), exclusiveto, contract] */
                MIDL_INTERFACE("96C9621A-C143-4392-BEDD-4A7E9574C8FD")
                IBrightnessOverride : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsSupported(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsOverrideActive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BrightnessLevel(
                        /* [retval, out] */__RPC__out DOUBLE * level
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetBrightnessLevel(
                        /* [in] */DOUBLE brightnessLevel,
                        /* [in] */ABI::Windows::Graphics::Display::DisplayBrightnessOverrideOptions options
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetBrightnessScenario(
                        /* [in] */ABI::Windows::Graphics::Display::DisplayBrightnessScenario scenario,
                        /* [in] */ABI::Windows::Graphics::Display::DisplayBrightnessOverrideOptions options
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetLevelForScenario(
                        /* [in] */ABI::Windows::Graphics::Display::DisplayBrightnessScenario scenario,
                        /* [retval, out] */__RPC__out DOUBLE * brightnessLevel
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE StartOverride(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE StopOverride(void) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_IsSupportedChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_IsSupportedChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_IsOverrideActiveChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_IsOverrideActiveChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_BrightnessLevelChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_BrightnessLevelChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IBrightnessOverride=_uuidof(IBrightnessOverride);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverrideSettings[] = L"Windows.Graphics.Display.IBrightnessOverrideSettings";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("D112AB2A-7604-4DBA-BCF8-4B6F49502CB0"), exclusiveto, contract] */
                MIDL_INTERFACE("D112AB2A-7604-4DBA-BCF8-4B6F49502CB0")
                IBrightnessOverrideSettings : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DesiredLevel(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DesiredNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IBrightnessOverrideSettings=_uuidof(IBrightnessOverrideSettings);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverrideSettingsStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics[] = L"Windows.Graphics.Display.IBrightnessOverrideSettingsStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("D487DC90-6F74-440B-B383-5FE96CF00B0F"), exclusiveto, contract] */
                MIDL_INTERFACE("D487DC90-6F74-440B-B383-5FE96CF00B0F")
                IBrightnessOverrideSettingsStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromLevel(
                        /* [in] */DOUBLE level,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IBrightnessOverrideSettings * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromNits(
                        /* [in] */FLOAT nits,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IBrightnessOverrideSettings * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateFromDisplayBrightnessOverrideScenario(
                        /* [in] */ABI::Windows::Graphics::Display::DisplayBrightnessOverrideScenario overrideScenario,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IBrightnessOverrideSettings * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IBrightnessOverrideSettingsStatics=_uuidof(IBrightnessOverrideSettingsStatics);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverrideStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverrideStatics[] = L"Windows.Graphics.Display.IBrightnessOverrideStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("03A7B9ED-E1F1-4A68-A11F-946AD8CE5393"), exclusiveto, contract] */
                MIDL_INTERFACE("03A7B9ED-E1F1-4A68-A11F-946AD8CE5393")
                IBrightnessOverrideStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDefaultForSystem(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IBrightnessOverride * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IBrightnessOverride * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SaveForSystemAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IBrightnessOverride * value,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IBrightnessOverrideStatics=_uuidof(IBrightnessOverrideStatics);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Graphics.Display.IColorOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.ColorOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IColorOverrideSettings[] = L"Windows.Graphics.Display.IColorOverrideSettings";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("FBEFA134-4A81-4C4D-A5B6-7D1B5C4BD00B"), exclusiveto, contract] */
                MIDL_INTERFACE("FBEFA134-4A81-4C4D-A5B6-7D1B5C4BD00B")
                IColorOverrideSettings : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DesiredDisplayColorOverrideScenario(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayColorOverrideScenario * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IColorOverrideSettings=_uuidof(IColorOverrideSettings);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IColorOverrideSettingsStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.ColorOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IColorOverrideSettingsStatics[] = L"Windows.Graphics.Display.IColorOverrideSettingsStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("B068E05F-C41F-4AC9-AFAB-827AB6248F9A"), exclusiveto, contract] */
                MIDL_INTERFACE("B068E05F-C41F-4AC9-AFAB-827AB6248F9A")
                IColorOverrideSettingsStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromDisplayColorOverrideScenario(
                        /* [in] */ABI::Windows::Graphics::Display::DisplayColorOverrideScenario overrideScenario,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IColorOverrideSettings * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IColorOverrideSettingsStatics=_uuidof(IColorOverrideSettingsStatics);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverride[] = L"Windows.Graphics.Display.IDisplayEnhancementOverride";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("429594CF-D97A-4B02-A428-5C4292F7F522"), exclusiveto, contract] */
                MIDL_INTERFACE("429594CF-D97A-4B02-A428-5C4292F7F522")
                IDisplayEnhancementOverride : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ColorOverrideSettings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IColorOverrideSettings * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ColorOverrideSettings(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IColorOverrideSettings * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BrightnessOverrideSettings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IBrightnessOverrideSettings * * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BrightnessOverrideSettings(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IBrightnessOverrideSettings * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanOverride(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsOverrideActive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentDisplayEnhancementOverrideCapabilities(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RequestOverride(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE StopOverride(void) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_CanOverrideChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_CanOverrideChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_IsOverrideActiveChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_IsOverrideActiveChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_DisplayEnhancementOverrideCapabilitiesChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_DisplayEnhancementOverrideCapabilitiesChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayEnhancementOverride=_uuidof(IDisplayEnhancementOverride);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilities
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverrideCapabilities
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities[] = L"Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilities";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("457060DE-EE5A-47B7-9918-1E51E812CCC8"), exclusiveto, contract] */
                MIDL_INTERFACE("457060DE-EE5A-47B7-9918-1E51E812CCC8")
                IDisplayEnhancementOverrideCapabilities : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsBrightnessControlSupported(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsBrightnessNitsControlSupported(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSupportedNitRanges(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayEnhancementOverrideCapabilities=_uuidof(IDisplayEnhancementOverrideCapabilities);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilitiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilitiesChangedEventArgs[] = L"Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilitiesChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("DB61E664-15FA-49DA-8B77-07DBD2AF585D"), exclusiveto, contract] */
                MIDL_INTERFACE("DB61E664-15FA-49DA-8B77-07DBD2AF585D")
                IDisplayEnhancementOverrideCapabilitiesChangedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Capabilities(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayEnhancementOverrideCapabilitiesChangedEventArgs=_uuidof(IDisplayEnhancementOverrideCapabilitiesChangedEventArgs);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverrideStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverrideStatics[] = L"Windows.Graphics.Display.IDisplayEnhancementOverrideStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("CF5B7EC1-9791-4453-B013-29B6F778E519"), exclusiveto, contract] */
                MIDL_INTERFACE("CF5B7EC1-9791-4453-B013-29B6F778E519")
                IDisplayEnhancementOverrideStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IDisplayEnhancementOverride * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayEnhancementOverrideStatics=_uuidof(IDisplayEnhancementOverrideStatics);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation[] = L"Windows.Graphics.Display.IDisplayInformation";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("BED112AE-ADC3-4DC9-AE65-851F4D7D4799"), exclusiveto, contract] */
                MIDL_INTERFACE("BED112AE-ADC3-4DC9-AE65-851F4D7D4799")
                IDisplayInformation : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CurrentOrientation(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayOrientations * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NativeOrientation(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayOrientations * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_OrientationChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_OrientationChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ResolutionScale(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::ResolutionScale * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LogicalDpi(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawDpiX(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawDpiY(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_DpiChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_DpiChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StereoEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_StereoEnabledChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_StereoEnabledChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetColorProfileAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * * asyncInfo
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ColorProfileChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ColorProfileChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayInformation=_uuidof(IDisplayInformation);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Graphics.Display.IDisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation2[] = L"Windows.Graphics.Display.IDisplayInformation2";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("4DCD0021-FAD1-4B8E-8EDF-775887B8BF19"), exclusiveto, contract] */
                MIDL_INTERFACE("4DCD0021-FAD1-4B8E-8EDF-775887B8BF19")
                IDisplayInformation2 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawPixelsPerViewPixel(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayInformation2=_uuidof(IDisplayInformation2);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation3[] = L"Windows.Graphics.Display.IDisplayInformation3";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("DB15011D-0F09-4466-8FF3-11DE9A3C929A"), exclusiveto, contract] */
                MIDL_INTERFACE("DB15011D-0F09-4466-8FF3-11DE9A3C929A")
                IDisplayInformation3 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DiagonalSizeInInches(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_double * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayInformation3=_uuidof(IDisplayInformation3);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation4
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation4[] = L"Windows.Graphics.Display.IDisplayInformation4";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("C972CE2F-1242-46BE-B536-E1AAFE9E7ACF"), exclusiveto, contract] */
                MIDL_INTERFACE("C972CE2F-1242-46BE-B536-E1AAFE9E7ACF")
                IDisplayInformation4 : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScreenWidthInRawPixels(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScreenHeightInRawPixels(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayInformation4=_uuidof(IDisplayInformation4);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation5
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation5[] = L"Windows.Graphics.Display.IDisplayInformation5";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("3A5442DC-2CDE-4A8D-80D1-21DC5ADCC1AA"), exclusiveto, contract] */
                MIDL_INTERFACE("3A5442DC-2CDE-4A8D-80D1-21DC5ADCC1AA")
                IDisplayInformation5 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetAdvancedColorInfo(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IAdvancedColorInfo * * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_AdvancedColorInfoChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_AdvancedColorInfoChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayInformation5=_uuidof(IDisplayInformation5);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformationStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformationStatics[] = L"Windows.Graphics.Display.IDisplayInformationStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("C6A02A6C-D452-44DC-BA07-96F3C6ADF9D1"), exclusiveto, contract] */
                MIDL_INTERFACE("C6A02A6C-D452-44DC-BA07-96F3C6ADF9D1")
                IDisplayInformationStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Display::IDisplayInformation * * current
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AutoRotationPreferences(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayOrientations * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AutoRotationPreferences(
                        /* [in] */ABI::Windows::Graphics::Display::DisplayOrientations value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_DisplayContentsInvalidated(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_DisplayContentsInvalidated(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayInformationStatics=_uuidof(IDisplayInformationStatics);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayPropertiesStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayProperties
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayPropertiesStatics[] = L"Windows.Graphics.Display.IDisplayPropertiesStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Display {
                /* [object, uuid("6937ED8D-30EA-4DED-8271-4553FF02F68A"), exclusiveto, deprecated, contract] */
                MIDL_INTERFACE("6937ED8D-30EA-4DED-8271-4553FF02F68A")
                
                #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                IDisplayPropertiesStatics : public IInspectable
                {
                public:
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propget, deprecated] */virtual HRESULT STDMETHODCALLTYPE get_CurrentOrientation(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayOrientations * value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propget, deprecated] */virtual HRESULT STDMETHODCALLTYPE get_NativeOrientation(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayOrientations * value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propget, deprecated] */virtual HRESULT STDMETHODCALLTYPE get_AutoRotationPreferences(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::DisplayOrientations * value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propput, deprecated] */virtual HRESULT STDMETHODCALLTYPE put_AutoRotationPreferences(
                        /* [in] */ABI::Windows::Graphics::Display::DisplayOrientations value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventadd, deprecated] */virtual HRESULT STDMETHODCALLTYPE add_OrientationChanged(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IDisplayPropertiesEventHandler  * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventremove, deprecated] */virtual HRESULT STDMETHODCALLTYPE remove_OrientationChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propget, deprecated] */virtual HRESULT STDMETHODCALLTYPE get_ResolutionScale(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::Display::ResolutionScale * value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propget, deprecated] */virtual HRESULT STDMETHODCALLTYPE get_LogicalDpi(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventadd, deprecated] */virtual HRESULT STDMETHODCALLTYPE add_LogicalDpiChanged(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IDisplayPropertiesEventHandler  * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventremove, deprecated] */virtual HRESULT STDMETHODCALLTYPE remove_LogicalDpiChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [propget, deprecated] */virtual HRESULT STDMETHODCALLTYPE get_StereoEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventadd, deprecated] */virtual HRESULT STDMETHODCALLTYPE add_StereoEnabledChanged(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IDisplayPropertiesEventHandler  * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventremove, deprecated] */virtual HRESULT STDMETHODCALLTYPE remove_StereoEnabledChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [deprecated] */virtual HRESULT STDMETHODCALLTYPE GetColorProfileAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * * asyncInfo
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventadd, deprecated] */virtual HRESULT STDMETHODCALLTYPE add_ColorProfileChanged(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IDisplayPropertiesEventHandler  * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventremove, deprecated] */virtual HRESULT STDMETHODCALLTYPE remove_ColorProfileChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventadd, deprecated] */virtual HRESULT STDMETHODCALLTYPE add_DisplayContentsInvalidated(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Display::IDisplayPropertiesEventHandler  * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    
                    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
                    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
                    /* [eventremove, deprecated] */virtual HRESULT STDMETHODCALLTYPE remove_DisplayContentsInvalidated(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayPropertiesStatics=_uuidof(IDisplayPropertiesStatics);
                
            } /* Display */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Graphics.Display.AdvancedColorInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IAdvancedColorInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_AdvancedColorInfo_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_AdvancedColorInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_AdvancedColorInfo[] = L"Windows.Graphics.Display.AdvancedColorInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.BrightnessOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IBrightnessOverrideStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IBrightnessOverride ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverride_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverride_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_BrightnessOverride[] = L"Windows.Graphics.Display.BrightnessOverride";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.Graphics.Display.BrightnessOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IBrightnessOverrideSettingsStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IBrightnessOverrideSettings ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverrideSettings_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverrideSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_BrightnessOverrideSettings[] = L"Windows.Graphics.Display.BrightnessOverrideSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.ColorOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IColorOverrideSettingsStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IColorOverrideSettings ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_ColorOverrideSettings_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_ColorOverrideSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_ColorOverrideSettings[] = L"Windows.Graphics.Display.ColorOverrideSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayEnhancementOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IDisplayEnhancementOverrideStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayEnhancementOverride ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverride_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverride_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayEnhancementOverride[] = L"Windows.Graphics.Display.DisplayEnhancementOverride";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayEnhancementOverrideCapabilities
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilities ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilities_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilities_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilities[] = L"Windows.Graphics.Display.DisplayEnhancementOverrideCapabilities";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilitiesChangedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilitiesChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilitiesChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilitiesChangedEventArgs[] = L"Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayInformation
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IDisplayInformationStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayInformation ** Default Interface **
 *    Windows.Graphics.Display.IDisplayInformation2
 *    Windows.Graphics.Display.IDisplayInformation3
 *    Windows.Graphics.Display.IDisplayInformation4
 *    Windows.Graphics.Display.IDisplayInformation5
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayInformation_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayInformation_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayInformation[] = L"Windows.Graphics.Display.DisplayInformation";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Graphics.Display.DisplayProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IDisplayPropertiesStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayProperties_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayProperties_DEFINED

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayProperties[] = L"Windows.Graphics.Display.DisplayProperties";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics;

#endif // ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions
struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange;

#if !defined(____FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CGraphics__CDisplay__CNitRange;

typedef struct __FIIterator_1_Windows__CGraphics__CDisplay__CNitRangeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CGraphics__CDisplay__CNitRangeVtbl;

interface __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange
{
    CONST_VTBL struct __FIIterator_1_Windows__CGraphics__CDisplay__CNitRangeVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__



#if !defined(____FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CGraphics__CDisplay__CNitRange;

typedef  struct __FIIterable_1_Windows__CGraphics__CDisplay__CNitRangeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CGraphics__CDisplay__CNitRange **first);

    END_INTERFACE
} __FIIterable_1_Windows__CGraphics__CDisplay__CNitRangeVtbl;

interface __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange
{
    CONST_VTBL struct __FIIterable_1_Windows__CGraphics__CDisplay__CNitRangeVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__



#if !defined(____FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange;

typedef struct __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRangeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
            /* [in] */ struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRangeVtbl;

interface __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange
{
    CONST_VTBL struct __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRangeVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange_INTERFACE_DEFINED__




#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

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


#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStreamVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStreamVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStreamVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream;

typedef struct __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStreamVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CStorage__CStreams__CIRandomAccessStream **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStream * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStreamVtbl;

interface __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStreamVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#if !defined(____FIReference_1_double_INTERFACE_DEFINED__)
#define ____FIReference_1_double_INTERFACE_DEFINED__

typedef interface __FIReference_1_double __FIReference_1_double;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_double;

typedef struct __FIReference_1_doubleVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_double * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_double * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_double * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_double * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_double * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_double * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_double * This, /* [retval][out] */ __RPC__out double *value);
    END_INTERFACE
} __FIReference_1_doubleVtbl;

interface __FIReference_1_double
{
    CONST_VTBL struct __FIReference_1_doubleVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_double_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_double_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_double_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_double_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_double_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_double_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_double_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_double_INTERFACE_DEFINED__




typedef struct __x_ABI_CWindows_CFoundation_CPoint __x_ABI_CWindows_CFoundation_CPoint;









typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CAdvancedColorKind __x_ABI_CWindows_CGraphics_CDisplay_CAdvancedColorKind;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideOptions __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideOptions;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideScenario __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideScenario;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessScenario __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessScenario;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayColorOverrideScenario __x_ABI_CWindows_CGraphics_CDisplay_CDisplayColorOverrideScenario;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CHdrMetadataFormat __x_ABI_CWindows_CGraphics_CDisplay_CHdrMetadataFormat;


typedef enum __x_ABI_CWindows_CGraphics_CDisplay_CResolutionScale __x_ABI_CWindows_CGraphics_CDisplay_CResolutionScale;


typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange __x_ABI_CWindows_CGraphics_CDisplay_CNitRange;





































/*
 *
 * Struct Windows.Graphics.Display.AdvancedColorKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CAdvancedColorKind
{
    AdvancedColorKind_StandardDynamicRange = 0,
    AdvancedColorKind_WideColorGamut = 1,
    AdvancedColorKind_HighDynamicRange = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.DisplayBrightnessOverrideOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideOptions
{
    DisplayBrightnessOverrideOptions_None = 0,
    DisplayBrightnessOverrideOptions_UseDimmedPolicyWhenBatteryIsLow = 0x1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.Display.DisplayBrightnessOverrideScenario
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideScenario
{
    DisplayBrightnessOverrideScenario_IdleBrightness = 0,
    DisplayBrightnessOverrideScenario_BarcodeReadingBrightness = 1,
    DisplayBrightnessOverrideScenario_FullBrightness = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.DisplayBrightnessScenario
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessScenario
{
    DisplayBrightnessScenario_DefaultBrightness = 0,
    DisplayBrightnessScenario_IdleBrightness = 1,
    DisplayBrightnessScenario_BarcodeReadingBrightness = 2,
    DisplayBrightnessScenario_FullBrightness = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.Display.DisplayColorOverrideScenario
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayColorOverrideScenario
{
    DisplayColorOverrideScenario_Accurate = 0,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.DisplayOrientations
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations
{
    DisplayOrientations_None = 0,
    DisplayOrientations_Landscape = 0x1,
    DisplayOrientations_Portrait = 0x2,
    DisplayOrientations_LandscapeFlipped = 0x4,
    DisplayOrientations_PortraitFlipped = 0x8,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Graphics.Display.HdrMetadataFormat
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CHdrMetadataFormat
{
    HdrMetadataFormat_Hdr10 = 0,
    HdrMetadataFormat_Hdr10Plus = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.Display.ResolutionScale
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CGraphics_CDisplay_CResolutionScale
{
    ResolutionScale_Invalid = 0,
    ResolutionScale_Scale100Percent = 100,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale120Percent = 120,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale125Percent = 125,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale140Percent = 140,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale150Percent = 150,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale160Percent = 160,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale175Percent = 175,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale180Percent = 180,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale200Percent = 200,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale225Percent = 225,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale250Percent = 250,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale300Percent = 300,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale350Percent = 350,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale400Percent = 400,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale450Percent = 450,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
    ResolutionScale_Scale500Percent = 500,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Struct Windows.Graphics.Display.NitRange
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

/* [contract] */
struct __x_ABI_CWindows_CGraphics_CDisplay_CNitRange
{
    FLOAT MinNits;
    FLOAT MaxNits;
    FLOAT StepSizeNits;
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Delegate Windows.Graphics.Display.DisplayPropertiesEventHandler
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_INTERFACE_DEFINED__
/* [object, uuid("DBDD8B01-F1A1-46D1-9EE3-543BCC995980"), deprecated, contract] */
typedef struct 
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
__x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandlerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject);

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler * This);

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler * This);
HRESULT ( STDMETHODCALLTYPE *Invoke )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler * This,
        /* [in] */__RPC__in_opt IInspectable * sender
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandlerVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandlerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_Invoke(This,sender) \
    ( (This)->lpVtbl->Invoke(This,sender) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IAdvancedColorInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.AdvancedColorInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IAdvancedColorInfo[] = L"Windows.Graphics.Display.IAdvancedColorInfo";
/* [object, uuid("8797DCFB-B229-4081-AE9A-2CC85E34AD6A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CurrentAdvancedColorKind )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CAdvancedColorKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RedPrimary )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_GreenPrimary )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BluePrimary )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WhitePoint )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxLuminanceInNits )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MinLuminanceInNits )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxAverageFullFrameLuminanceInNits )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SdrWhiteLevelInNits )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    HRESULT ( STDMETHODCALLTYPE *IsHdrMetadataFormatCurrentlySupported )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CHdrMetadataFormat format,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *IsAdvancedColorKindAvailable )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CAdvancedColorKind kind,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfoVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_CurrentAdvancedColorKind(This,value) \
    ( (This)->lpVtbl->get_CurrentAdvancedColorKind(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_RedPrimary(This,value) \
    ( (This)->lpVtbl->get_RedPrimary(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_GreenPrimary(This,value) \
    ( (This)->lpVtbl->get_GreenPrimary(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_BluePrimary(This,value) \
    ( (This)->lpVtbl->get_BluePrimary(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_WhitePoint(This,value) \
    ( (This)->lpVtbl->get_WhitePoint(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_MaxLuminanceInNits(This,value) \
    ( (This)->lpVtbl->get_MaxLuminanceInNits(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_MinLuminanceInNits(This,value) \
    ( (This)->lpVtbl->get_MinLuminanceInNits(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_MaxAverageFullFrameLuminanceInNits(This,value) \
    ( (This)->lpVtbl->get_MaxAverageFullFrameLuminanceInNits(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_get_SdrWhiteLevelInNits(This,value) \
    ( (This)->lpVtbl->get_SdrWhiteLevelInNits(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_IsHdrMetadataFormatCurrentlySupported(This,format,result) \
    ( (This)->lpVtbl->IsHdrMetadataFormatCurrentlySupported(This,format,result) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_IsAdvancedColorKindAvailable(This,kind,result) \
    ( (This)->lpVtbl->IsAdvancedColorKindAvailable(This,kind,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverride[] = L"Windows.Graphics.Display.IBrightnessOverride";
/* [object, uuid("96C9621A-C143-4392-BEDD-4A7E9574C8FD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsSupported )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsOverrideActive )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BrightnessLevel )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [retval, out] */__RPC__out DOUBLE * level
        );
    HRESULT ( STDMETHODCALLTYPE *SetBrightnessLevel )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */DOUBLE brightnessLevel,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideOptions options
        );
    HRESULT ( STDMETHODCALLTYPE *SetBrightnessScenario )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessScenario scenario,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideOptions options
        );
    HRESULT ( STDMETHODCALLTYPE *GetLevelForScenario )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessScenario scenario,
        /* [retval, out] */__RPC__out DOUBLE * brightnessLevel
        );
    HRESULT ( STDMETHODCALLTYPE *StartOverride )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This
        );
    HRESULT ( STDMETHODCALLTYPE *StopOverride )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_IsSupportedChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_IsSupportedChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_IsOverrideActiveChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_IsOverrideActiveChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_BrightnessLevelChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CBrightnessOverride_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_BrightnessLevelChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_get_IsSupported(This,value) \
    ( (This)->lpVtbl->get_IsSupported(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_get_IsOverrideActive(This,value) \
    ( (This)->lpVtbl->get_IsOverrideActive(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_get_BrightnessLevel(This,level) \
    ( (This)->lpVtbl->get_BrightnessLevel(This,level) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_SetBrightnessLevel(This,brightnessLevel,options) \
    ( (This)->lpVtbl->SetBrightnessLevel(This,brightnessLevel,options) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_SetBrightnessScenario(This,scenario,options) \
    ( (This)->lpVtbl->SetBrightnessScenario(This,scenario,options) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_GetLevelForScenario(This,scenario,brightnessLevel) \
    ( (This)->lpVtbl->GetLevelForScenario(This,scenario,brightnessLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_StartOverride(This) \
    ( (This)->lpVtbl->StartOverride(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_StopOverride(This) \
    ( (This)->lpVtbl->StopOverride(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_add_IsSupportedChanged(This,handler,token) \
    ( (This)->lpVtbl->add_IsSupportedChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_remove_IsSupportedChanged(This,token) \
    ( (This)->lpVtbl->remove_IsSupportedChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_add_IsOverrideActiveChanged(This,handler,token) \
    ( (This)->lpVtbl->add_IsOverrideActiveChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_remove_IsOverrideActiveChanged(This,token) \
    ( (This)->lpVtbl->remove_IsOverrideActiveChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_add_BrightnessLevelChanged(This,handler,token) \
    ( (This)->lpVtbl->add_BrightnessLevelChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_remove_BrightnessLevelChanged(This,token) \
    ( (This)->lpVtbl->remove_BrightnessLevelChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverrideSettings[] = L"Windows.Graphics.Display.IBrightnessOverrideSettings";
/* [object, uuid("D112AB2A-7604-4DBA-BCF8-4B6F49502CB0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DesiredLevel )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DesiredNits )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_get_DesiredLevel(This,value) \
    ( (This)->lpVtbl->get_DesiredLevel(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_get_DesiredNits(This,value) \
    ( (This)->lpVtbl->get_DesiredNits(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverrideSettingsStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics[] = L"Windows.Graphics.Display.IBrightnessOverrideSettingsStatics";
/* [object, uuid("D487DC90-6F74-440B-B383-5FE96CF00B0F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromLevel )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
        /* [in] */DOUBLE level,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromNits )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
        /* [in] */FLOAT nits,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateFromDisplayBrightnessOverrideScenario )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayBrightnessOverrideScenario overrideScenario,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_CreateFromLevel(This,level,result) \
    ( (This)->lpVtbl->CreateFromLevel(This,level,result) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_CreateFromNits(This,nits,result) \
    ( (This)->lpVtbl->CreateFromNits(This,nits,result) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_CreateFromDisplayBrightnessOverrideScenario(This,overrideScenario,result) \
    ( (This)->lpVtbl->CreateFromDisplayBrightnessOverrideScenario(This,overrideScenario,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettingsStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IBrightnessOverrideStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.BrightnessOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IBrightnessOverrideStatics[] = L"Windows.Graphics.Display.IBrightnessOverrideStatics";
/* [object, uuid("03A7B9ED-E1F1-4A68-A11F-946AD8CE5393"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDefaultForSystem )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * * value
        );
    HRESULT ( STDMETHODCALLTYPE *SaveForSystemAsync )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverride * value,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_GetDefaultForSystem(This,value) \
    ( (This)->lpVtbl->GetDefaultForSystem(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_GetForCurrentView(This,value) \
    ( (This)->lpVtbl->GetForCurrentView(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_SaveForSystemAsync(This,value,operation) \
    ( (This)->lpVtbl->SaveForSystemAsync(This,value,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Graphics.Display.IColorOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.ColorOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IColorOverrideSettings[] = L"Windows.Graphics.Display.IColorOverrideSettings";
/* [object, uuid("FBEFA134-4A81-4C4D-A5B6-7D1B5C4BD00B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DesiredDisplayColorOverrideScenario )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayColorOverrideScenario * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_get_DesiredDisplayColorOverrideScenario(This,value) \
    ( (This)->lpVtbl->get_DesiredDisplayColorOverrideScenario(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IColorOverrideSettingsStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.ColorOverrideSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IColorOverrideSettingsStatics[] = L"Windows.Graphics.Display.IColorOverrideSettingsStatics";
/* [object, uuid("B068E05F-C41F-4AC9-AFAB-827AB6248F9A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromDisplayColorOverrideScenario )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayColorOverrideScenario overrideScenario,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_CreateFromDisplayColorOverrideScenario(This,overrideScenario,result) \
    ( (This)->lpVtbl->CreateFromDisplayColorOverrideScenario(This,overrideScenario,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettingsStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverride[] = L"Windows.Graphics.Display.IDisplayEnhancementOverride";
/* [object, uuid("429594CF-D97A-4B02-A428-5C4292F7F522"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ColorOverrideSettings )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ColorOverrideSettings )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIColorOverrideSettings * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BrightnessOverrideSettings )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BrightnessOverrideSettings )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIBrightnessOverrideSettings * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanOverride )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsOverrideActive )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetCurrentDisplayEnhancementOverrideCapabilities )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * * value
        );
    HRESULT ( STDMETHODCALLTYPE *RequestOverride )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This
        );
    HRESULT ( STDMETHODCALLTYPE *StopOverride )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_CanOverrideChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_CanOverrideChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_IsOverrideActiveChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_IsOverrideActiveChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_DisplayEnhancementOverrideCapabilitiesChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayEnhancementOverride_Windows__CGraphics__CDisplay__CDisplayEnhancementOverrideCapabilitiesChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_DisplayEnhancementOverrideCapabilitiesChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_get_ColorOverrideSettings(This,value) \
    ( (This)->lpVtbl->get_ColorOverrideSettings(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_put_ColorOverrideSettings(This,value) \
    ( (This)->lpVtbl->put_ColorOverrideSettings(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_get_BrightnessOverrideSettings(This,value) \
    ( (This)->lpVtbl->get_BrightnessOverrideSettings(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_put_BrightnessOverrideSettings(This,value) \
    ( (This)->lpVtbl->put_BrightnessOverrideSettings(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_get_CanOverride(This,value) \
    ( (This)->lpVtbl->get_CanOverride(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_get_IsOverrideActive(This,value) \
    ( (This)->lpVtbl->get_IsOverrideActive(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_GetCurrentDisplayEnhancementOverrideCapabilities(This,value) \
    ( (This)->lpVtbl->GetCurrentDisplayEnhancementOverrideCapabilities(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_RequestOverride(This) \
    ( (This)->lpVtbl->RequestOverride(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_StopOverride(This) \
    ( (This)->lpVtbl->StopOverride(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_add_CanOverrideChanged(This,handler,token) \
    ( (This)->lpVtbl->add_CanOverrideChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_remove_CanOverrideChanged(This,token) \
    ( (This)->lpVtbl->remove_CanOverrideChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_add_IsOverrideActiveChanged(This,handler,token) \
    ( (This)->lpVtbl->add_IsOverrideActiveChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_remove_IsOverrideActiveChanged(This,token) \
    ( (This)->lpVtbl->remove_IsOverrideActiveChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_add_DisplayEnhancementOverrideCapabilitiesChanged(This,handler,token) \
    ( (This)->lpVtbl->add_DisplayEnhancementOverrideCapabilitiesChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_remove_DisplayEnhancementOverrideCapabilitiesChanged(This,token) \
    ( (This)->lpVtbl->remove_DisplayEnhancementOverrideCapabilitiesChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilities
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverrideCapabilities
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities[] = L"Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilities";
/* [object, uuid("457060DE-EE5A-47B7-9918-1E51E812CCC8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsBrightnessControlSupported )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsBrightnessNitsControlSupported )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetSupportedNitRanges )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CGraphics__CDisplay__CNitRange * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_get_IsBrightnessControlSupported(This,value) \
    ( (This)->lpVtbl->get_IsBrightnessControlSupported(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_get_IsBrightnessNitsControlSupported(This,value) \
    ( (This)->lpVtbl->get_IsBrightnessNitsControlSupported(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_GetSupportedNitRanges(This,result) \
    ( (This)->lpVtbl->GetSupportedNitRanges(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilitiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilitiesChangedEventArgs[] = L"Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilitiesChangedEventArgs";
/* [object, uuid("DB61E664-15FA-49DA-8B77-07DBD2AF585D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Capabilities )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilities * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_get_Capabilities(This,value) \
    ( (This)->lpVtbl->get_Capabilities(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideCapabilitiesChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayEnhancementOverrideStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayEnhancementOverride
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayEnhancementOverrideStatics[] = L"Windows.Graphics.Display.IDisplayEnhancementOverrideStatics";
/* [object, uuid("CF5B7EC1-9791-4453-B013-29B6F778E519"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverride * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_GetForCurrentView(This,result) \
    ( (This)->lpVtbl->GetForCurrentView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayEnhancementOverrideStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation[] = L"Windows.Graphics.Display.IDisplayInformation";
/* [object, uuid("BED112AE-ADC3-4DC9-AE65-851F4D7D4799"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CurrentOrientation )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NativeOrientation )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_OrientationChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_OrientationChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ResolutionScale )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CResolutionScale * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LogicalDpi )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawDpiX )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawDpiY )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_DpiChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_DpiChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StereoEnabled )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_StereoEnabledChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_StereoEnabledChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *GetColorProfileAsync )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * * asyncInfo
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ColorProfileChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ColorProfileChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_CurrentOrientation(This,value) \
    ( (This)->lpVtbl->get_CurrentOrientation(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_NativeOrientation(This,value) \
    ( (This)->lpVtbl->get_NativeOrientation(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_add_OrientationChanged(This,handler,token) \
    ( (This)->lpVtbl->add_OrientationChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_remove_OrientationChanged(This,token) \
    ( (This)->lpVtbl->remove_OrientationChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_ResolutionScale(This,value) \
    ( (This)->lpVtbl->get_ResolutionScale(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_LogicalDpi(This,value) \
    ( (This)->lpVtbl->get_LogicalDpi(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_RawDpiX(This,value) \
    ( (This)->lpVtbl->get_RawDpiX(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_RawDpiY(This,value) \
    ( (This)->lpVtbl->get_RawDpiY(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_add_DpiChanged(This,handler,token) \
    ( (This)->lpVtbl->add_DpiChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_remove_DpiChanged(This,token) \
    ( (This)->lpVtbl->remove_DpiChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_get_StereoEnabled(This,value) \
    ( (This)->lpVtbl->get_StereoEnabled(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_add_StereoEnabledChanged(This,handler,token) \
    ( (This)->lpVtbl->add_StereoEnabledChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_remove_StereoEnabledChanged(This,token) \
    ( (This)->lpVtbl->remove_StereoEnabledChanged(This,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_GetColorProfileAsync(This,asyncInfo) \
    ( (This)->lpVtbl->GetColorProfileAsync(This,asyncInfo) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_add_ColorProfileChanged(This,handler,token) \
    ( (This)->lpVtbl->add_ColorProfileChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_remove_ColorProfileChanged(This,token) \
    ( (This)->lpVtbl->remove_ColorProfileChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Graphics.Display.IDisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation2[] = L"Windows.Graphics.Display.IDisplayInformation2";
/* [object, uuid("4DCD0021-FAD1-4B8E-8EDF-775887B8BF19"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawPixelsPerViewPixel )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2 * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2Vtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_get_RawPixelsPerViewPixel(This,value) \
    ( (This)->lpVtbl->get_RawPixelsPerViewPixel(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 2.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x20000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation3[] = L"Windows.Graphics.Display.IDisplayInformation3";
/* [object, uuid("DB15011D-0F09-4466-8FF3-11DE9A3C929A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DiagonalSizeInInches )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3 * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_double * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3Vtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_get_DiagonalSizeInInches(This,value) \
    ( (This)->lpVtbl->get_DiagonalSizeInInches(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x20000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation4
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation4[] = L"Windows.Graphics.Display.IDisplayInformation4";
/* [object, uuid("C972CE2F-1242-46BE-B536-E1AAFE9E7ACF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScreenWidthInRawPixels )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScreenHeightInRawPixels )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4 * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4Vtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_get_ScreenWidthInRawPixels(This,value) \
    ( (This)->lpVtbl->get_ScreenWidthInRawPixels(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_get_ScreenHeightInRawPixels(This,value) \
    ( (This)->lpVtbl->get_ScreenHeightInRawPixels(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation4_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformation5
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformation5[] = L"Windows.Graphics.Display.IDisplayInformation5";
/* [object, uuid("3A5442DC-2CDE-4A8D-80D1-21DC5ADCC1AA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetAdvancedColorInfo )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIAdvancedColorInfo * * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_AdvancedColorInfoChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_AdvancedColorInfoChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5 * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5Vtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_GetAdvancedColorInfo(This,value) \
    ( (This)->lpVtbl->GetAdvancedColorInfo(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_add_AdvancedColorInfoChanged(This,handler,token) \
    ( (This)->lpVtbl->add_AdvancedColorInfoChanged(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_remove_AdvancedColorInfoChanged(This,token) \
    ( (This)->lpVtbl->remove_AdvancedColorInfoChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation5_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayInformationStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayInformation
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayInformationStatics[] = L"Windows.Graphics.Display.IDisplayInformationStatics";
/* [object, uuid("C6A02A6C-D452-44DC-BA07-96F3C6ADF9D1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformation * * current
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AutoRotationPreferences )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AutoRotationPreferences )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_DisplayContentsInvalidated )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CDisplay__CDisplayInformation_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_DisplayContentsInvalidated )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_GetForCurrentView(This,current) \
    ( (This)->lpVtbl->GetForCurrentView(This,current) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_get_AutoRotationPreferences(This,value) \
    ( (This)->lpVtbl->get_AutoRotationPreferences(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_put_AutoRotationPreferences(This,value) \
    ( (This)->lpVtbl->put_AutoRotationPreferences(This,value) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_add_DisplayContentsInvalidated(This,handler,token) \
    ( (This)->lpVtbl->add_DisplayContentsInvalidated(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_remove_DisplayContentsInvalidated(This,token) \
    ( (This)->lpVtbl->remove_DisplayContentsInvalidated(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayInformationStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Graphics.Display.IDisplayPropertiesStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Display.DisplayProperties
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Display_IDisplayPropertiesStatics[] = L"Windows.Graphics.Display.IDisplayPropertiesStatics";
/* [object, uuid("6937ED8D-30EA-4DED-8271-4553FF02F68A"), exclusiveto, deprecated, contract] */
typedef struct 
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
__x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );

    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propget, deprecated] */HRESULT ( STDMETHODCALLTYPE *get_CurrentOrientation )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations * value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propget, deprecated] */HRESULT ( STDMETHODCALLTYPE *get_NativeOrientation )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations * value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propget, deprecated] */HRESULT ( STDMETHODCALLTYPE *get_AutoRotationPreferences )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations * value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propput, deprecated] */HRESULT ( STDMETHODCALLTYPE *put_AutoRotationPreferences )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDisplay_CDisplayOrientations value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventadd, deprecated] */HRESULT ( STDMETHODCALLTYPE *add_OrientationChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler  * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventremove, deprecated] */HRESULT ( STDMETHODCALLTYPE *remove_OrientationChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */EventRegistrationToken token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propget, deprecated] */HRESULT ( STDMETHODCALLTYPE *get_ResolutionScale )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplay_CResolutionScale * value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propget, deprecated] */HRESULT ( STDMETHODCALLTYPE *get_LogicalDpi )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventadd, deprecated] */HRESULT ( STDMETHODCALLTYPE *add_LogicalDpiChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler  * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventremove, deprecated] */HRESULT ( STDMETHODCALLTYPE *remove_LogicalDpiChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */EventRegistrationToken token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [propget, deprecated] */HRESULT ( STDMETHODCALLTYPE *get_StereoEnabled )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventadd, deprecated] */HRESULT ( STDMETHODCALLTYPE *add_StereoEnabledChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler  * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventremove, deprecated] */HRESULT ( STDMETHODCALLTYPE *remove_StereoEnabledChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */EventRegistrationToken token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [deprecated] */HRESULT ( STDMETHODCALLTYPE *GetColorProfileAsync )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CStorage__CStreams__CIRandomAccessStream * * asyncInfo
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventadd, deprecated] */HRESULT ( STDMETHODCALLTYPE *add_ColorProfileChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler  * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventremove, deprecated] */HRESULT ( STDMETHODCALLTYPE *remove_ColorProfileChanged )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */EventRegistrationToken token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventadd, deprecated] */HRESULT ( STDMETHODCALLTYPE *add_DisplayContentsInvalidated )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesEventHandler  * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    
    #if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
    #endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
    /* [eventremove, deprecated] */HRESULT ( STDMETHODCALLTYPE *remove_DisplayContentsInvalidated )(
        __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_get_CurrentOrientation(This,value) \
    ( (This)->lpVtbl->get_CurrentOrientation(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_get_NativeOrientation(This,value) \
    ( (This)->lpVtbl->get_NativeOrientation(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_get_AutoRotationPreferences(This,value) \
    ( (This)->lpVtbl->get_AutoRotationPreferences(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_put_AutoRotationPreferences(This,value) \
    ( (This)->lpVtbl->put_AutoRotationPreferences(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_add_OrientationChanged(This,handler,token) \
    ( (This)->lpVtbl->add_OrientationChanged(This,handler,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_remove_OrientationChanged(This,token) \
    ( (This)->lpVtbl->remove_OrientationChanged(This,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_get_ResolutionScale(This,value) \
    ( (This)->lpVtbl->get_ResolutionScale(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_get_LogicalDpi(This,value) \
    ( (This)->lpVtbl->get_LogicalDpi(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_add_LogicalDpiChanged(This,handler,token) \
    ( (This)->lpVtbl->add_LogicalDpiChanged(This,handler,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_remove_LogicalDpiChanged(This,token) \
    ( (This)->lpVtbl->remove_LogicalDpiChanged(This,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_get_StereoEnabled(This,value) \
    ( (This)->lpVtbl->get_StereoEnabled(This,value) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_add_StereoEnabledChanged(This,handler,token) \
    ( (This)->lpVtbl->add_StereoEnabledChanged(This,handler,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_remove_StereoEnabledChanged(This,token) \
    ( (This)->lpVtbl->remove_StereoEnabledChanged(This,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_GetColorProfileAsync(This,asyncInfo) \
    ( (This)->lpVtbl->GetColorProfileAsync(This,asyncInfo) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_add_ColorProfileChanged(This,handler,token) \
    ( (This)->lpVtbl->add_ColorProfileChanged(This,handler,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_remove_ColorProfileChanged(This,token) \
    ( (This)->lpVtbl->remove_ColorProfileChanged(This,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_add_DisplayContentsInvalidated(This,handler,token) \
    ( (This)->lpVtbl->add_DisplayContentsInvalidated(This,handler,token) )


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#define __x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_remove_DisplayContentsInvalidated(This,token) \
    ( (This)->lpVtbl->remove_DisplayContentsInvalidated(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CDisplay_CIDisplayPropertiesStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Graphics.Display.AdvancedColorInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IAdvancedColorInfo ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_AdvancedColorInfo_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_AdvancedColorInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_AdvancedColorInfo[] = L"Windows.Graphics.Display.AdvancedColorInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.BrightnessOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IBrightnessOverrideStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IBrightnessOverride ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverride_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverride_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_BrightnessOverride[] = L"Windows.Graphics.Display.BrightnessOverride";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.Graphics.Display.BrightnessOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IBrightnessOverrideSettingsStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IBrightnessOverrideSettings ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverrideSettings_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_BrightnessOverrideSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_BrightnessOverrideSettings[] = L"Windows.Graphics.Display.BrightnessOverrideSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.ColorOverrideSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IColorOverrideSettingsStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IColorOverrideSettings ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_ColorOverrideSettings_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_ColorOverrideSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_ColorOverrideSettings[] = L"Windows.Graphics.Display.ColorOverrideSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayEnhancementOverride
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IDisplayEnhancementOverrideStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayEnhancementOverride ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverride_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverride_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayEnhancementOverride[] = L"Windows.Graphics.Display.DisplayEnhancementOverride";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayEnhancementOverrideCapabilities
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilities ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilities_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilities_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilities[] = L"Windows.Graphics.Display.DisplayEnhancementOverrideCapabilities";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayEnhancementOverrideCapabilitiesChangedEventArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilitiesChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilitiesChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayEnhancementOverrideCapabilitiesChangedEventArgs[] = L"Windows.Graphics.Display.DisplayEnhancementOverrideCapabilitiesChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Display.DisplayInformation
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IDisplayInformationStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Display.IDisplayInformation ** Default Interface **
 *    Windows.Graphics.Display.IDisplayInformation2
 *    Windows.Graphics.Display.IDisplayInformation3
 *    Windows.Graphics.Display.IDisplayInformation4
 *    Windows.Graphics.Display.IDisplayInformation5
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayInformation_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayInformation_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayInformation[] = L"Windows.Graphics.Display.DisplayInformation";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Graphics.Display.DisplayProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 1.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Display.IDisplayPropertiesStatics interface starting with version 1.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#ifndef RUNTIMECLASS_Windows_Graphics_Display_DisplayProperties_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Display_DisplayProperties_DEFINED

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
DEPRECATED("DisplayProperties may be altered or unavailable for releases after Windows Phone 8.1. Instead, use DisplayInformation.")
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Display_DisplayProperties[] = L"Windows.Graphics.Display.DisplayProperties";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Egraphics2Edisplay_p_h__

#endif // __windows2Egraphics2Edisplay_h__
