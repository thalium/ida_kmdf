/* Header file automatically generated from windows.devices.lights.effects.idl */
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
#ifndef __windows2Edevices2Elights2Eeffects_h__
#define __windows2Edevices2Elights2Eeffects_h__
#ifndef __windows2Edevices2Elights2Eeffects_p_h__
#define __windows2Edevices2Elights2Eeffects_p_h__


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
#include "Windows.Devices.Lights.h"
#include "Windows.Graphics.Imaging.h"
#include "Windows.UI.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayBitmapEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayBitmapEffectFactory;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapEffectFactory

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayBitmapRequestedEventArgs;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayBlinkEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect ABI::Windows::Devices::Lights::Effects::ILampArrayBlinkEffect

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayBlinkEffectFactory;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory ABI::Windows::Devices::Lights::Effects::ILampArrayBlinkEffectFactory

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayColorRampEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect ABI::Windows::Devices::Lights::Effects::ILampArrayColorRampEffect

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayColorRampEffectFactory;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory ABI::Windows::Devices::Lights::Effects::ILampArrayColorRampEffectFactory

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayCustomEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect ABI::Windows::Devices::Lights::Effects::ILampArrayCustomEffect

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayCustomEffectFactory;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory ABI::Windows::Devices::Lights::Effects::ILampArrayCustomEffectFactory

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect ABI::Windows::Devices::Lights::Effects::ILampArrayEffect

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayEffectPlaylist;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayEffectPlaylistStatics;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylistStatics

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArraySolidEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect ABI::Windows::Devices::Lights::Effects::ILampArraySolidEffect

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArraySolidEffectFactory;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory ABI::Windows::Devices::Lights::Effects::ILampArraySolidEffectFactory

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    interface ILampArrayUpdateRequestedEventArgs;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs ABI::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE
#define DEF___FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("de51580c-48a6-50b5-976b-05894699015a"))
IIterator<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> : IIterator_impl<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Devices.Lights.Effects.ILampArrayEffect>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t;
#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*>
//#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE
#define DEF___FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("3f108d37-6679-5590-aed2-033362fbf413"))
IIterable<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> : IIterable_impl<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Devices.Lights.Effects.ILampArrayEffect>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t;
#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*>
//#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE
#define DEF___FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("97159586-9fb0-56d4-9df4-8c36ea15100e"))
IVectorView<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> : IVectorView_impl<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Devices.Lights.Effects.ILampArrayEffect>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*> __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t;
#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*>
//#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::Lights::Effects::ILampArrayEffect*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayEffectPlaylist;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_USE
#define DEF___FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("2aaabbc2-4c18-5d1c-9e09-c1249eb46817"))
IIterator<ABI::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist*, ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Devices.Lights.Effects.LampArrayEffectPlaylist>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist*> __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_t;
#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist*>
//#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_USE
#define DEF___FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("2314acda-c5df-5051-977d-94d79d1312fb"))
IIterable<ABI::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist*, ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Devices.Lights.Effects.LampArrayEffectPlaylist>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist*> __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_t;
#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist*>
//#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayBitmapEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayBitmapRequestedEventArgs;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("24b5818b-448e-53fa-ab4c-663008c5d4cf"))
ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::LampArrayBitmapEffect*,ABI::Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Effects::LampArrayBitmapEffect*, ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs*, ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Lights.Effects.LampArrayBitmapEffect, Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::LampArrayBitmapEffect*,ABI::Windows::Devices::Lights::Effects::LampArrayBitmapRequestedEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect*,ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect*,ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayCustomEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayUpdateRequestedEventArgs;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("7d91af6e-ba44-5a0f-bc64-3901fd33661c"))
ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::LampArrayCustomEffect*,ABI::Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Effects::LampArrayCustomEffect*, ABI::Windows::Devices::Lights::Effects::ILampArrayCustomEffect*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs*, ABI::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Lights.Effects.LampArrayCustomEffect, Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::LampArrayCustomEffect*,ABI::Windows::Devices::Lights::Effects::LampArrayUpdateRequestedEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::ILampArrayCustomEffect*,ABI::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Lights::Effects::ILampArrayCustomEffect*,ABI::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                class LampArray;
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

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





namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Size Size;
            
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
        namespace Graphics {
            namespace Imaging {
                class SoftwareBitmap;
            } /* Imaging */
        } /* Graphics */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Imaging {
                interface ISoftwareBitmap;
            } /* Imaging */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap ABI::Windows::Graphics::Imaging::ISoftwareBitmap

#endif // ____x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap_FWD_DEFINED__





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
                namespace Effects {
                    
                    typedef enum LampArrayEffectCompletionBehavior : int LampArrayEffectCompletionBehavior;
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    
                    typedef enum LampArrayEffectStartMode : int LampArrayEffectStartMode;
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    
                    typedef enum LampArrayRepetitionMode : int LampArrayRepetitionMode;
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


















namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayBlinkEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArrayColorRampEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    class LampArraySolidEffect;
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */













/*
 *
 * Struct Windows.Devices.Lights.Effects.LampArrayEffectCompletionBehavior
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
                namespace Effects {
                    /* [v1_enum, contract] */
                    enum LampArrayEffectCompletionBehavior : int
                    {
                        LampArrayEffectCompletionBehavior_ClearState = 0,
                        LampArrayEffectCompletionBehavior_KeepState = 1,
                    };
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.Devices.Lights.Effects.LampArrayEffectStartMode
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
                namespace Effects {
                    /* [v1_enum, contract] */
                    enum LampArrayEffectStartMode : int
                    {
                        LampArrayEffectStartMode_Sequential = 0,
                        LampArrayEffectStartMode_Simultaneous = 1,
                    };
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.Devices.Lights.Effects.LampArrayRepetitionMode
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
                namespace Effects {
                    /* [v1_enum, contract] */
                    enum LampArrayRepetitionMode : int
                    {
                        LampArrayRepetitionMode_Occurrences = 0,
                        LampArrayRepetitionMode_Forever = 1,
                    };
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBitmapEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBitmapEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayBitmapEffect";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("3238E065-D877-4627-89E5-2A88F7052FA6"), exclusiveto, contract] */
                    MIDL_INTERFACE("3238E065-D877-4627-89E5-2A88F7052FA6")
                    ILampArrayBitmapEffect : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Duration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Duration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartDelay(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StartDelay(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UpdateInterval(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_UpdateInterval(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SuggestedBitmapSize(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Size * value
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_BitmapRequested(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_BitmapRequested(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayBitmapEffect=_uuidof(ILampArrayBitmapEffect);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBitmapEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBitmapEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("13608090-E336-4C8F-9053-A92407CA7B1D"), exclusiveto, contract] */
                    MIDL_INTERFACE("13608090-E336-4C8F-9053-A92407CA7B1D")
                    ILampArrayBitmapEffectFactory : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateInstance(
                            /* [in] */__RPC__in_opt ABI::Windows::Devices::Lights::ILampArray * lampArray,
                            /* [in] */UINT32 __lampIndexesSize,
                            /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayBitmapEffectFactory=_uuidof(ILampArrayBitmapEffectFactory);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBitmapRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("C8B4AF9E-FE63-4D51-BABD-619DEFB454BA"), exclusiveto, contract] */
                    MIDL_INTERFACE("C8B4AF9E-FE63-4D51-BABD-619DEFB454BA")
                    ILampArrayBitmapRequestedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SinceStarted(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE UpdateBitmap(
                            /* [in] */__RPC__in_opt ABI::Windows::Graphics::Imaging::ISoftwareBitmap * bitmap
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayBitmapRequestedEventArgs=_uuidof(ILampArrayBitmapRequestedEventArgs);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBlinkEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBlinkEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayBlinkEffect";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("EBBF35F6-2FC5-4BB3-B3C3-6221A7680D13"), exclusiveto, contract] */
                    MIDL_INTERFACE("EBBF35F6-2FC5-4BB3-B3C3-6221A7680D13")
                    ILampArrayBlinkEffect : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Color(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Color(
                            /* [in] */ABI::Windows::UI::Color value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AttackDuration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AttackDuration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SustainDuration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_SustainDuration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DecayDuration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DecayDuration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RepetitionDelay(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RepetitionDelay(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartDelay(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StartDelay(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Occurrences(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Occurrences(
                            /* [in] */INT32 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RepetitionMode(
                            /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::Effects::LampArrayRepetitionMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RepetitionMode(
                            /* [in] */ABI::Windows::Devices::Lights::Effects::LampArrayRepetitionMode value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayBlinkEffect=_uuidof(ILampArrayBlinkEffect);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBlinkEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBlinkEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("879F1D97-9F50-49B2-A56F-013AA08D55E0"), exclusiveto, contract] */
                    MIDL_INTERFACE("879F1D97-9F50-49B2-A56F-013AA08D55E0")
                    ILampArrayBlinkEffectFactory : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateInstance(
                            /* [in] */__RPC__in_opt ABI::Windows::Devices::Lights::ILampArray * lampArray,
                            /* [in] */UINT32 __lampIndexesSize,
                            /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Lights::Effects::ILampArrayBlinkEffect * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayBlinkEffectFactory=_uuidof(ILampArrayBlinkEffectFactory);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayColorRampEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayColorRampEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayColorRampEffect";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("2B004437-40A7-432E-A0B9-0D570C2153FF"), exclusiveto, contract] */
                    MIDL_INTERFACE("2B004437-40A7-432E-A0B9-0D570C2153FF")
                    ILampArrayColorRampEffect : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Color(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Color(
                            /* [in] */ABI::Windows::UI::Color value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RampDuration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RampDuration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartDelay(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StartDelay(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CompletionBehavior(
                            /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_CompletionBehavior(
                            /* [in] */ABI::Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayColorRampEffect=_uuidof(ILampArrayColorRampEffect);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayColorRampEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayColorRampEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("520BD133-0C74-4DF5-BEA7-4899E0266B0F"), exclusiveto, contract] */
                    MIDL_INTERFACE("520BD133-0C74-4DF5-BEA7-4899E0266B0F")
                    ILampArrayColorRampEffectFactory : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateInstance(
                            /* [in] */__RPC__in_opt ABI::Windows::Devices::Lights::ILampArray * lampArray,
                            /* [in] */UINT32 __lampIndexesSize,
                            /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Lights::Effects::ILampArrayColorRampEffect * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayColorRampEffectFactory=_uuidof(ILampArrayColorRampEffectFactory);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayCustomEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayCustomEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayCustomEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayCustomEffect";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("EC579170-3C34-4876-818B-5765F78B0EE4"), exclusiveto, contract] */
                    MIDL_INTERFACE("EC579170-3C34-4876-818B-5765F78B0EE4")
                    ILampArrayCustomEffect : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Duration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Duration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UpdateInterval(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_UpdateInterval(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_UpdateRequested(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_UpdateRequested(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayCustomEffect=_uuidof(ILampArrayCustomEffect);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayCustomEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayCustomEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("68B4774D-63E5-4AF0-A58B-3E535B94E8C9"), exclusiveto, contract] */
                    MIDL_INTERFACE("68B4774D-63E5-4AF0-A58B-3E535B94E8C9")
                    ILampArrayCustomEffectFactory : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateInstance(
                            /* [in] */__RPC__in_opt ABI::Windows::Devices::Lights::ILampArray * lampArray,
                            /* [in] */UINT32 __lampIndexesSize,
                            /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Lights::Effects::ILampArrayCustomEffect * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayCustomEffectFactory=_uuidof(ILampArrayCustomEffectFactory);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayEffect";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("11D45590-57FB-4546-B1CE-863107F740DF"), contract] */
                    MIDL_INTERFACE("11D45590-57FB-4546-B1CE-863107F740DF")
                    ILampArrayEffect : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ZIndex(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ZIndex(
                            /* [in] */INT32 value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayEffect=_uuidof(ILampArrayEffect);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayEffectPlaylist
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist[] = L"Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("7DE58BFE-6F61-4103-98C7-D6632F7B9169"), exclusiveto, contract] */
                    MIDL_INTERFACE("7DE58BFE-6F61-4103-98C7-D6632F7B9169")
                    ILampArrayEffectPlaylist : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Append(
                            /* [in] */__RPC__in_opt ABI::Windows::Devices::Lights::Effects::ILampArrayEffect * effect
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE OverrideZIndex(
                            /* [in] */INT32 zIndex
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Start(void) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Stop(void) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Pause(void) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EffectStartMode(
                            /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::Effects::LampArrayEffectStartMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_EffectStartMode(
                            /* [in] */ABI::Windows::Devices::Lights::Effects::LampArrayEffectStartMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Occurrences(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Occurrences(
                            /* [in] */INT32 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RepetitionMode(
                            /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::Effects::LampArrayRepetitionMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RepetitionMode(
                            /* [in] */ABI::Windows::Devices::Lights::Effects::LampArrayRepetitionMode value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayEffectPlaylist=_uuidof(ILampArrayEffectPlaylist);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayEffectPlaylist
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics[] = L"Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("FB15235C-EA35-4C7F-A016-F3BFC6A6C47D"), exclusiveto, contract] */
                    MIDL_INTERFACE("FB15235C-EA35-4C7F-A016-F3BFC6A6C47D")
                    ILampArrayEffectPlaylistStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE StartAll(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE StopAll(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE PauseAll(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayEffectPlaylistStatics=_uuidof(ILampArrayEffectPlaylistStatics);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArraySolidEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArraySolidEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArraySolidEffect[] = L"Windows.Devices.Lights.Effects.ILampArraySolidEffect";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("441F8213-43CC-4B33-80EB-C6DDDE7DC8ED"), exclusiveto, contract] */
                    MIDL_INTERFACE("441F8213-43CC-4B33-80EB-C6DDDE7DC8ED")
                    ILampArraySolidEffect : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Color(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Color * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Color(
                            /* [in] */ABI::Windows::UI::Color value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Duration(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Duration(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartDelay(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_StartDelay(
                            /* [in] */ABI::Windows::Foundation::TimeSpan value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CompletionBehavior(
                            /* [retval, out] */__RPC__out ABI::Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_CompletionBehavior(
                            /* [in] */ABI::Windows::Devices::Lights::Effects::LampArrayEffectCompletionBehavior value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArraySolidEffect=_uuidof(ILampArraySolidEffect);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArraySolidEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArraySolidEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("F862A32C-5576-4341-961B-AEE1F13CF9DD"), exclusiveto, contract] */
                    MIDL_INTERFACE("F862A32C-5576-4341-961B-AEE1F13CF9DD")
                    ILampArraySolidEffectFactory : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateInstance(
                            /* [in] */__RPC__in_opt ABI::Windows::Devices::Lights::ILampArray * lampArray,
                            /* [in] */UINT32 __lampIndexesSize,
                            /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Lights::Effects::ILampArraySolidEffect * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArraySolidEffectFactory=_uuidof(ILampArraySolidEffectFactory);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Lights {
                namespace Effects {
                    /* [object, uuid("73560D6A-576A-48AF-8539-67FFA0AB3516"), exclusiveto, contract] */
                    MIDL_INTERFACE("73560D6A-576A-48AF-8539-67FFA0AB3516")
                    ILampArrayUpdateRequestedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SinceStarted(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
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
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ILampArrayUpdateRequestedEventArgs=_uuidof(ILampArrayUpdateRequestedEventArgs);
                    
                } /* Effects */
            } /* Lights */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayBitmapEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayBitmapEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayBitmapEffect[] = L"Windows.Devices.Lights.Effects.LampArrayBitmapEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayBitmapRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayBlinkEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayBlinkEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBlinkEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBlinkEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayBlinkEffect[] = L"Windows.Devices.Lights.Effects.LampArrayBlinkEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayColorRampEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayColorRampEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayColorRampEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayColorRampEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayColorRampEffect[] = L"Windows.Devices.Lights.Effects.LampArrayColorRampEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayCustomEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayCustomEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayCustomEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayCustomEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayCustomEffect[] = L"Windows.Devices.Lights.Effects.LampArrayCustomEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayEffectPlaylist
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist ** Default Interface **
 *    Windows.Foundation.Collections.IVectorView_1_Windows.Devices.Lights.Effects.ILampArrayEffect
 *    Windows.Foundation.Collections.IIterable_1_Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayEffectPlaylist_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayEffectPlaylist_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayEffectPlaylist[] = L"Windows.Devices.Lights.Effects.LampArrayEffectPlaylist";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArraySolidEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArraySolidEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArraySolidEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArraySolidEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArraySolidEffect[] = L"Windows.Devices.Lights.Effects.LampArraySolidEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayUpdateRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayUpdateRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayUpdateRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect;

typedef struct __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl;

interface __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect
{
    CONST_VTBL struct __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect;

typedef  struct __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect **first);

    END_INTERFACE
} __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl;

interface __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect
{
    CONST_VTBL struct __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect;

typedef struct __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
            /* [in] */ __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl;

interface __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect
{
    CONST_VTBL struct __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffectVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CDevices__CLights__CEffects__CILampArrayEffect_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist;

typedef struct __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylistVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylistVtbl;

interface __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist
{
    CONST_VTBL struct __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylistVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist;

typedef  struct __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylistVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist **first);

    END_INTERFACE
} __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylistVtbl;

interface __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist
{
    CONST_VTBL struct __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylistVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#ifndef ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CLights_CILampArray __x_ABI_CWindows_CDevices_CLights_CILampArray;

#endif // ____x_ABI_CWindows_CDevices_CLights_CILampArray_FWD_DEFINED__






typedef struct __x_ABI_CWindows_CFoundation_CSize __x_ABI_CWindows_CFoundation_CSize;


typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;




#ifndef ____x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap __x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap;

#endif // ____x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap_FWD_DEFINED__






typedef struct __x_ABI_CWindows_CUI_CColor __x_ABI_CWindows_CUI_CColor;




typedef enum __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior;


typedef enum __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectStartMode __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectStartMode;


typedef enum __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode;


































/*
 *
 * Struct Windows.Devices.Lights.Effects.LampArrayEffectCompletionBehavior
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior
{
    LampArrayEffectCompletionBehavior_ClearState = 0,
    LampArrayEffectCompletionBehavior_KeepState = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.Devices.Lights.Effects.LampArrayEffectStartMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectStartMode
{
    LampArrayEffectStartMode_Sequential = 0,
    LampArrayEffectStartMode_Simultaneous = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.Devices.Lights.Effects.LampArrayRepetitionMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode
{
    LampArrayRepetitionMode_Occurrences = 0,
    LampArrayRepetitionMode_Forever = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBitmapEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBitmapEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBitmapEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayBitmapEffect";
/* [object, uuid("3238E065-D877-4627-89E5-2A88F7052FA6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Duration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Duration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UpdateInterval )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_UpdateInterval )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SuggestedBitmapSize )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CSize * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_BitmapRequested )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayBitmapEffect_Windows__CDevices__CLights__CEffects__CLampArrayBitmapRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_BitmapRequested )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_get_Duration(This,value) \
    ( (This)->lpVtbl->get_Duration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_put_Duration(This,value) \
    ( (This)->lpVtbl->put_Duration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_get_StartDelay(This,value) \
    ( (This)->lpVtbl->get_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_put_StartDelay(This,value) \
    ( (This)->lpVtbl->put_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_get_UpdateInterval(This,value) \
    ( (This)->lpVtbl->get_UpdateInterval(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_put_UpdateInterval(This,value) \
    ( (This)->lpVtbl->put_UpdateInterval(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_get_SuggestedBitmapSize(This,value) \
    ( (This)->lpVtbl->get_SuggestedBitmapSize(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_add_BitmapRequested(This,handler,token) \
    ( (This)->lpVtbl->add_BitmapRequested(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_remove_BitmapRequested(This,token) \
    ( (This)->lpVtbl->remove_BitmapRequested(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBitmapEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBitmapEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory";
/* [object, uuid("13608090-E336-4C8F-9053-A92407CA7B1D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateInstance )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILampArray * lampArray,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffect * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactoryVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) \
    ( (This)->lpVtbl->CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBitmapRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs";
/* [object, uuid("C8B4AF9E-FE63-4D51-BABD-619DEFB454BA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SinceStarted )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    HRESULT ( STDMETHODCALLTYPE *UpdateBitmap )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CImaging_CISoftwareBitmap * bitmap
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_get_SinceStarted(This,value) \
    ( (This)->lpVtbl->get_SinceStarted(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_UpdateBitmap(This,bitmap) \
    ( (This)->lpVtbl->UpdateBitmap(This,bitmap) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBitmapRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBlinkEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBlinkEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBlinkEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayBlinkEffect";
/* [object, uuid("EBBF35F6-2FC5-4BB3-B3C3-6221A7680D13"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Color )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Color )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AttackDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AttackDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SustainDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_SustainDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DecayDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DecayDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RepetitionDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RepetitionDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Occurrences )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Occurrences )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */INT32 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RepetitionMode )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RepetitionMode )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * This,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_Color(This,value) \
    ( (This)->lpVtbl->get_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_Color(This,value) \
    ( (This)->lpVtbl->put_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_AttackDuration(This,value) \
    ( (This)->lpVtbl->get_AttackDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_AttackDuration(This,value) \
    ( (This)->lpVtbl->put_AttackDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_SustainDuration(This,value) \
    ( (This)->lpVtbl->get_SustainDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_SustainDuration(This,value) \
    ( (This)->lpVtbl->put_SustainDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_DecayDuration(This,value) \
    ( (This)->lpVtbl->get_DecayDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_DecayDuration(This,value) \
    ( (This)->lpVtbl->put_DecayDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_RepetitionDelay(This,value) \
    ( (This)->lpVtbl->get_RepetitionDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_RepetitionDelay(This,value) \
    ( (This)->lpVtbl->put_RepetitionDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_StartDelay(This,value) \
    ( (This)->lpVtbl->get_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_StartDelay(This,value) \
    ( (This)->lpVtbl->put_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_Occurrences(This,value) \
    ( (This)->lpVtbl->get_Occurrences(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_Occurrences(This,value) \
    ( (This)->lpVtbl->put_Occurrences(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_get_RepetitionMode(This,value) \
    ( (This)->lpVtbl->get_RepetitionMode(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_put_RepetitionMode(This,value) \
    ( (This)->lpVtbl->put_RepetitionMode(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayBlinkEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayBlinkEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory";
/* [object, uuid("879F1D97-9F50-49B2-A56F-013AA08D55E0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateInstance )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILampArray * lampArray,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffect * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactoryVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) \
    ( (This)->lpVtbl->CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayBlinkEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayColorRampEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayColorRampEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayColorRampEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayColorRampEffect";
/* [object, uuid("2B004437-40A7-432E-A0B9-0D570C2153FF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Color )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Color )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RampDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RampDuration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CompletionBehavior )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_CompletionBehavior )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * This,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_get_Color(This,value) \
    ( (This)->lpVtbl->get_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_put_Color(This,value) \
    ( (This)->lpVtbl->put_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_get_RampDuration(This,value) \
    ( (This)->lpVtbl->get_RampDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_put_RampDuration(This,value) \
    ( (This)->lpVtbl->put_RampDuration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_get_StartDelay(This,value) \
    ( (This)->lpVtbl->get_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_put_StartDelay(This,value) \
    ( (This)->lpVtbl->put_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_get_CompletionBehavior(This,value) \
    ( (This)->lpVtbl->get_CompletionBehavior(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_put_CompletionBehavior(This,value) \
    ( (This)->lpVtbl->put_CompletionBehavior(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayColorRampEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayColorRampEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory";
/* [object, uuid("520BD133-0C74-4DF5-BEA7-4899E0266B0F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateInstance )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILampArray * lampArray,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffect * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactoryVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) \
    ( (This)->lpVtbl->CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayColorRampEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayCustomEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayCustomEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayCustomEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayCustomEffect";
/* [object, uuid("EC579170-3C34-4876-818B-5765F78B0EE4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Duration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Duration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UpdateInterval )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_UpdateInterval )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_UpdateRequested )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CLights__CEffects__CLampArrayCustomEffect_Windows__CDevices__CLights__CEffects__CLampArrayUpdateRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_UpdateRequested )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_get_Duration(This,value) \
    ( (This)->lpVtbl->get_Duration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_put_Duration(This,value) \
    ( (This)->lpVtbl->put_Duration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_get_UpdateInterval(This,value) \
    ( (This)->lpVtbl->get_UpdateInterval(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_put_UpdateInterval(This,value) \
    ( (This)->lpVtbl->put_UpdateInterval(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_add_UpdateRequested(This,handler,token) \
    ( (This)->lpVtbl->add_UpdateRequested(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_remove_UpdateRequested(This,token) \
    ( (This)->lpVtbl->remove_UpdateRequested(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayCustomEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayCustomEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory";
/* [object, uuid("68B4774D-63E5-4AF0-A58B-3E535B94E8C9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateInstance )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILampArray * lampArray,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffect * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactoryVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) \
    ( (This)->lpVtbl->CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayCustomEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayEffect[] = L"Windows.Devices.Lights.Effects.ILampArrayEffect";
/* [object, uuid("11D45590-57FB-4546-B1CE-863107F740DF"), contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ZIndex )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ZIndex )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * This,
        /* [in] */INT32 value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_get_ZIndex(This,value) \
    ( (This)->lpVtbl->get_ZIndex(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_put_ZIndex(This,value) \
    ( (This)->lpVtbl->put_ZIndex(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayEffectPlaylist
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylist[] = L"Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist";
/* [object, uuid("7DE58BFE-6F61-4103-98C7-D6632F7B9169"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Append )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffect * effect
        );
    HRESULT ( STDMETHODCALLTYPE *OverrideZIndex )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [in] */INT32 zIndex
        );
    HRESULT ( STDMETHODCALLTYPE *Start )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This
        );
    HRESULT ( STDMETHODCALLTYPE *Stop )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This
        );
    HRESULT ( STDMETHODCALLTYPE *Pause )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EffectStartMode )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectStartMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_EffectStartMode )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectStartMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Occurrences )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Occurrences )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [in] */INT32 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RepetitionMode )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RepetitionMode )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist * This,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayRepetitionMode value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_Append(This,effect) \
    ( (This)->lpVtbl->Append(This,effect) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_OverrideZIndex(This,zIndex) \
    ( (This)->lpVtbl->OverrideZIndex(This,zIndex) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_Start(This) \
    ( (This)->lpVtbl->Start(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_Stop(This) \
    ( (This)->lpVtbl->Stop(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_Pause(This) \
    ( (This)->lpVtbl->Pause(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_get_EffectStartMode(This,value) \
    ( (This)->lpVtbl->get_EffectStartMode(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_put_EffectStartMode(This,value) \
    ( (This)->lpVtbl->put_EffectStartMode(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_get_Occurrences(This,value) \
    ( (This)->lpVtbl->get_Occurrences(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_put_Occurrences(This,value) \
    ( (This)->lpVtbl->put_Occurrences(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_get_RepetitionMode(This,value) \
    ( (This)->lpVtbl->get_RepetitionMode(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_put_RepetitionMode(This,value) \
    ( (This)->lpVtbl->put_RepetitionMode(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylist_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayEffectPlaylist
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayEffectPlaylistStatics[] = L"Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics";
/* [object, uuid("FB15235C-EA35-4C7F-A016-F3BFC6A6C47D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *StartAll )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * value
        );
    HRESULT ( STDMETHODCALLTYPE *StopAll )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * value
        );
    HRESULT ( STDMETHODCALLTYPE *PauseAll )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CDevices__CLights__CEffects__CLampArrayEffectPlaylist * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStaticsVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_StartAll(This,value) \
    ( (This)->lpVtbl->StartAll(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_StopAll(This,value) \
    ( (This)->lpVtbl->StopAll(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_PauseAll(This,value) \
    ( (This)->lpVtbl->PauseAll(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayEffectPlaylistStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArraySolidEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArraySolidEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArraySolidEffect[] = L"Windows.Devices.Lights.Effects.ILampArraySolidEffect";
/* [object, uuid("441F8213-43CC-4B33-80EB-C6DDDE7DC8ED"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Color )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CColor * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Color )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Duration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Duration )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_StartDelay )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CompletionBehavior )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_CompletionBehavior )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * This,
        /* [in] */__x_ABI_CWindows_CDevices_CLights_CEffects_CLampArrayEffectCompletionBehavior value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_get_Color(This,value) \
    ( (This)->lpVtbl->get_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_put_Color(This,value) \
    ( (This)->lpVtbl->put_Color(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_get_Duration(This,value) \
    ( (This)->lpVtbl->get_Duration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_put_Duration(This,value) \
    ( (This)->lpVtbl->put_Duration(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_get_StartDelay(This,value) \
    ( (This)->lpVtbl->get_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_put_StartDelay(This,value) \
    ( (This)->lpVtbl->put_StartDelay(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_get_CompletionBehavior(This,value) \
    ( (This)->lpVtbl->get_CompletionBehavior(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_put_CompletionBehavior(This,value) \
    ( (This)->lpVtbl->put_CompletionBehavior(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArraySolidEffect
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArraySolidEffectFactory[] = L"Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory";
/* [object, uuid("F862A32C-5576-4341-961B-AEE1F13CF9DD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateInstance )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CDevices_CLights_CILampArray * lampArray,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffect * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactoryVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) \
    ( (This)->lpVtbl->CreateInstance(This,lampArray,__lampIndexesSize,lampIndexes,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArraySolidEffectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Lights_Effects_ILampArrayUpdateRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs";
/* [object, uuid("73560D6A-576A-48AF-8539-67FFA0AB3516"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SinceStarted )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    HRESULT ( STDMETHODCALLTYPE *SetColor )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorForIndex )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
        /* [in] */INT32 lampIndex,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor
        );
    HRESULT ( STDMETHODCALLTYPE *SetSingleColorForIndices )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
        /* [in] */__x_ABI_CWindows_CUI_CColor desiredColor,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes
        );
    HRESULT ( STDMETHODCALLTYPE *SetColorsForIndices )(
        __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs * This,
        /* [in] */UINT32 __desiredColorsSize,
        /* [size_is(__desiredColorsSize), in] */__RPC__in_ecount_full(__desiredColorsSize) __x_ABI_CWindows_CUI_CColor * desiredColors,
        /* [in] */UINT32 __lampIndexesSize,
        /* [size_is(__lampIndexesSize), in] */__RPC__in_ecount_full(__lampIndexesSize) INT32 * lampIndexes
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_get_SinceStarted(This,value) \
    ( (This)->lpVtbl->get_SinceStarted(This,value) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_SetColor(This,desiredColor) \
    ( (This)->lpVtbl->SetColor(This,desiredColor) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_SetColorForIndex(This,lampIndex,desiredColor) \
    ( (This)->lpVtbl->SetColorForIndex(This,lampIndex,desiredColor) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_SetSingleColorForIndices(This,desiredColor,__lampIndexesSize,lampIndexes) \
    ( (This)->lpVtbl->SetSingleColorForIndices(This,desiredColor,__lampIndexesSize,lampIndexes) )

#define __x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_SetColorsForIndices(This,__desiredColorsSize,desiredColors,__lampIndexesSize,lampIndexes) \
    ( (This)->lpVtbl->SetColorsForIndices(This,__desiredColorsSize,desiredColors,__lampIndexesSize,lampIndexes) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CLights_CEffects_CILampArrayUpdateRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayBitmapEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayBitmapEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayBitmapEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayBitmapEffect[] = L"Windows.Devices.Lights.Effects.LampArrayBitmapEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayBitmapRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBitmapRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayBitmapRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.LampArrayBitmapRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayBlinkEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayBlinkEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayBlinkEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBlinkEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayBlinkEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayBlinkEffect[] = L"Windows.Devices.Lights.Effects.LampArrayBlinkEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayColorRampEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayColorRampEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayColorRampEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayColorRampEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayColorRampEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayColorRampEffect[] = L"Windows.Devices.Lights.Effects.LampArrayColorRampEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayCustomEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArrayCustomEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayCustomEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayCustomEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayCustomEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayCustomEffect[] = L"Windows.Devices.Lights.Effects.LampArrayCustomEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayEffectPlaylist
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Lights.Effects.ILampArrayEffectPlaylistStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayEffectPlaylist ** Default Interface **
 *    Windows.Foundation.Collections.IVectorView_1_Windows.Devices.Lights.Effects.ILampArrayEffect
 *    Windows.Foundation.Collections.IIterable_1_Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayEffectPlaylist_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayEffectPlaylist_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayEffectPlaylist[] = L"Windows.Devices.Lights.Effects.LampArrayEffectPlaylist";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArraySolidEffect
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Devices.Lights.Effects.ILampArraySolidEffectFactory interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArraySolidEffect ** Default Interface **
 *    Windows.Devices.Lights.Effects.ILampArrayEffect
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArraySolidEffect_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArraySolidEffect_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArraySolidEffect[] = L"Windows.Devices.Lights.Effects.LampArraySolidEffect";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Lights.Effects.ILampArrayUpdateRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayUpdateRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Lights_Effects_LampArrayUpdateRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Lights_Effects_LampArrayUpdateRequestedEventArgs[] = L"Windows.Devices.Lights.Effects.LampArrayUpdateRequestedEventArgs";
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
#endif // __windows2Edevices2Elights2Eeffects_p_h__

#endif // __windows2Edevices2Elights2Eeffects_h__
