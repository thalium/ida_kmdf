/* Header file automatically generated from windows.media.miracast.idl */
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
#ifndef __windows2Emedia2Emiracast_h__
#define __windows2Emedia2Emiracast_h__
#ifndef __windows2Emedia2Emiracast_p_h__
#define __windows2Emedia2Emiracast_p_h__


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
#include "Windows.ApplicationModel.Core.h"
#include "Windows.Graphics.h"
#include "Windows.Media.Core.h"
#include "Windows.Storage.Streams.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiver;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver ABI::Windows::Media::Miracast::IMiracastReceiver

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverApplySettingsResult;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverConnection;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection ABI::Windows::Media::Miracast::IMiracastReceiverConnection

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverConnectionCreatedEventArgs;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs ABI::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverCursorImageChannel;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverCursorImageChannelSettings;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverDisconnectedEventArgs;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs ABI::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverGameControllerDevice;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice ABI::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverInputDevices;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices ABI::Windows::Media::Miracast::IMiracastReceiverInputDevices

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverKeyboardDevice;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice ABI::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverMediaSourceCreatedEventArgs;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs ABI::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverSession;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession ABI::Windows::Media::Miracast::IMiracastReceiverSession

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverSessionStartResult;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverSettings;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings ABI::Windows::Media::Miracast::IMiracastReceiverSettings

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverStatus;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus ABI::Windows::Media::Miracast::IMiracastReceiverStatus

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverStreamControl;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl ABI::Windows::Media::Miracast::IMiracastReceiverStreamControl

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastReceiverVideoStreamSettings;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                interface IMiracastTransmitter;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter ABI::Windows::Media::Miracast::IMiracastTransmitter

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverConnection;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE
#define DEF___FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("618a96b9-8b3b-5dbb-acf6-b015ff651785"))
IIterator<ABI::Windows::Media::Miracast::MiracastReceiverConnection*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverConnection*, ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Media.Miracast.MiracastReceiverConnection>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Media::Miracast::MiracastReceiverConnection*> __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t;
#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>
//#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE
#define DEF___FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e989eb90-1f6f-5084-9bfb-1a5decca4f23"))
IIterable<ABI::Windows::Media::Miracast::MiracastReceiverConnection*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverConnection*, ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Media.Miracast.MiracastReceiverConnection>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Media::Miracast::MiracastReceiverConnection*> __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t;
#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>
//#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastTransmitter;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE
#define DEF___FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("f903966b-1c85-5726-af5b-afc28a3b3cf4"))
IIterator<ABI::Windows::Media::Miracast::MiracastTransmitter*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastTransmitter*, ABI::Windows::Media::Miracast::IMiracastTransmitter*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Media.Miracast.MiracastTransmitter>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Media::Miracast::MiracastTransmitter*> __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t;
#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Media::Miracast::IMiracastTransmitter*>
//#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Media::Miracast::IMiracastTransmitter*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE
#define DEF___FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5a3f4149-9b6b-5ff0-85a0-fea37b0990eb"))
IIterable<ABI::Windows::Media::Miracast::MiracastTransmitter*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastTransmitter*, ABI::Windows::Media::Miracast::IMiracastTransmitter*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Media.Miracast.MiracastTransmitter>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Media::Miracast::MiracastTransmitter*> __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t;
#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Media::Miracast::IMiracastTransmitter*>
//#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Media::Miracast::IMiracastTransmitter*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE
#define DEF___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("98ac8f8c-2322-54cf-b2c6-7a56a9d2220b"))
IVectorView<ABI::Windows::Media::Miracast::MiracastReceiverConnection*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverConnection*, ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Media.Miracast.MiracastReceiverConnection>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Media::Miracast::MiracastReceiverConnection*> __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t;
#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>
//#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Media::Miracast::IMiracastReceiverConnection*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE
#define DEF___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("4e1bf46c-49f6-5892-bcf7-80564ea2b606"))
IVectorView<ABI::Windows::Media::Miracast::MiracastTransmitter*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastTransmitter*, ABI::Windows::Media::Miracast::IMiracastTransmitter*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Media.Miracast.MiracastTransmitter>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Media::Miracast::MiracastTransmitter*> __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t;
#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Media::Miracast::IMiracastTransmitter*>
//#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Media::Miracast::IMiracastTransmitter*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverApplySettingsResult;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("afcb4574-7ac3-56ea-9a6a-cf535f0cf01e"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsResult*, ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Miracast.MiracastReceiverApplySettingsResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsResult*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("6fec734b-823d-5b06-ad81-0455f97f556f"))
IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsResult*, ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Miracast.MiracastReceiverApplySettingsResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsResult*> __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_t;
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult*>
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverSession;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("9d4308cb-4bcf-5b1b-b8b3-0484de9f3537"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSession*, ABI::Windows::Media::Miracast::IMiracastReceiverSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Miracast.MiracastReceiverSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("5ab880e1-2c0d-5d2f-bf95-037515624a8c"))
IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverSession*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSession*, ABI::Windows::Media::Miracast::IMiracastReceiverSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Miracast.MiracastReceiverSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverSession*> __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_t;
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverSession*>
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverSessionStartResult;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("eb315ed3-f94b-5fcc-9512-98ac9d8a423f"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverSessionStartResult*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSessionStartResult*, ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Miracast.MiracastReceiverSessionStartResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverSessionStartResult*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("a4520f20-1984-52e5-9b70-15a9ce94aef8"))
IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverSessionStartResult*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSessionStartResult*, ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Miracast.MiracastReceiverSessionStartResult>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverSessionStartResult*> __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_t;
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult*>
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverSettings;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("5e89ca08-40e1-52f6-8649-04841e01820d"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverSettings*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSettings*, ABI::Windows::Media::Miracast::IMiracastReceiverSettings*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Miracast.MiracastReceiverSettings>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverSettings*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSettings*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSettings*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("922c5527-4300-5995-8ddc-923dd4ba7010"))
IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverSettings*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSettings*, ABI::Windows::Media::Miracast::IMiracastReceiverSettings*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Miracast.MiracastReceiverSettings>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverSettings*> __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_t;
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverSettings*>
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverSettings*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverStatus;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("8243f2be-82a3-5335-b3c9-ae653b3b695c"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverStatus*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverStatus*, ABI::Windows::Media::Miracast::IMiracastReceiverStatus*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Miracast.MiracastReceiverStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverStatus*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverStatus*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverStatus*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("aa26649e-265d-5e79-8eef-a7fe894dc9f2"))
IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverStatus*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverStatus*, ABI::Windows::Media::Miracast::IMiracastReceiverStatus*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Miracast.MiracastReceiverStatus>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverStatus*> __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_t;
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverStatus*>
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverStatus*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverVideoStreamSettings;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b88cbc92-b616-57d1-9f9b-6bba5d5acfa9"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings*, ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Miracast.MiracastReceiverVideoStreamSettings>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("67ca293b-c811-57b2-b4fc-007b7efb64a0"))
IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings*, ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Miracast.MiracastReceiverVideoStreamSettings>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Miracast::MiracastReceiverVideoStreamSettings*> __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_t;
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings*>
//#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiver;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("44eb06ea-0014-5aed-83a1-95d225d06688"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiver*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiver*, ABI::Windows::Media::Miracast::IMiracastReceiver*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiver, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiver*,IInspectable*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiver*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiver*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverCursorImageChannel;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("401d6f64-cb30-59c3-a663-f84ab6edf1fa"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverCursorImageChannel*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverCursorImageChannel*, ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiverCursorImageChannel, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverCursorImageChannel*,IInspectable*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverGameControllerDevice;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("10a9d2a7-5049-5e19-9d22-72da7d6bb643"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverGameControllerDevice*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverGameControllerDevice*, ABI::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiverGameControllerDevice, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverGameControllerDevice*,IInspectable*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverKeyboardDevice;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("97d896c7-a5ea-5209-92c0-a0278087afd1"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverKeyboardDevice*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverKeyboardDevice*, ABI::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiverKeyboardDevice, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverKeyboardDevice*,IInspectable*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverConnectionCreatedEventArgs;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("69d03828-7a8a-549a-8253-7850e4db605a"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*,ABI::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSession*, ABI::Windows::Media::Miracast::IMiracastReceiverSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs*, ABI::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiverSession, Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*,ABI::Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*,ABI::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*,ABI::Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverDisconnectedEventArgs;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("a4964b5f-147c-57e3-82d0-cc7de5ff2def"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*,ABI::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSession*, ABI::Windows::Media::Miracast::IMiracastReceiverSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs*, ABI::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiverSession, Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*,ABI::Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*,ABI::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*,ABI::Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverMediaSourceCreatedEventArgs;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("929ec57a-92cc-50f8-ae4a-bb6a67152e82"))
ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*,ABI::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverSession*, ABI::Windows::Media::Miracast::IMiracastReceiverSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs*, ABI::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Miracast.MiracastReceiverSession, Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Miracast::MiracastReceiverSession*,ABI::Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*,ABI::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Miracast::IMiracastReceiverSession*,ABI::Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Core {
                class CoreApplicationView;
            } /* Core */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Core {
                interface ICoreApplicationView;
            } /* Core */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView ABI::Windows::ApplicationModel::Core::ICoreApplicationView

#endif // ____x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView_FWD_DEFINED__





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
        namespace Graphics {
            
            typedef struct PointInt32 PointInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct SizeInt32 SizeInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Core {
                class MediaSource;
            } /* Core */
        } /* Media */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CMedia_CCore_CIMediaSource2_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CCore_CIMediaSource2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Core {
                interface IMediaSource2;
            } /* Core */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CCore_CIMediaSource2 ABI::Windows::Media::Core::IMediaSource2

#endif // ____x_ABI_CWindows_CMedia_CCore_CIMediaSource2_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            namespace Streams {
                interface IRandomAccessStreamWithContentType;
            } /* Streams */
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType ABI::Windows::Storage::Streams::IRandomAccessStreamWithContentType

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverApplySettingsStatus : int MiracastReceiverApplySettingsStatus;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverAuthorizationMethod : int MiracastReceiverAuthorizationMethod;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverDisconnectReason : int MiracastReceiverDisconnectReason;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverGameControllerDeviceUsageMode : int MiracastReceiverGameControllerDeviceUsageMode;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverListeningStatus : int MiracastReceiverListeningStatus;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverSessionStartStatus : int MiracastReceiverSessionStartStatus;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastReceiverWiFiStatus : int MiracastReceiverWiFiStatus;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                
                typedef enum MiracastTransmitterAuthorizationStatus : int MiracastTransmitterAuthorizationStatus;
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
























namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverCursorImageChannelSettings;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverInputDevices;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */








namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                class MiracastReceiverStreamControl;
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */












/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverApplySettingsStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverApplySettingsStatus : int
                {
                    MiracastReceiverApplySettingsStatus_Success = 0,
                    MiracastReceiverApplySettingsStatus_UnknownFailure = 1,
                    MiracastReceiverApplySettingsStatus_MiracastNotSupported = 2,
                    MiracastReceiverApplySettingsStatus_AccessDenied = 3,
                    MiracastReceiverApplySettingsStatus_FriendlyNameTooLong = 4,
                    MiracastReceiverApplySettingsStatus_ModelNameTooLong = 5,
                    MiracastReceiverApplySettingsStatus_ModelNumberTooLong = 6,
                    MiracastReceiverApplySettingsStatus_InvalidSettings = 7,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverAuthorizationMethod
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverAuthorizationMethod : int
                {
                    MiracastReceiverAuthorizationMethod_None = 0,
                    MiracastReceiverAuthorizationMethod_ConfirmConnection = 1,
                    MiracastReceiverAuthorizationMethod_PinDisplayIfRequested = 2,
                    MiracastReceiverAuthorizationMethod_PinDisplayRequired = 3,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverDisconnectReason
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverDisconnectReason : int
                {
                    MiracastReceiverDisconnectReason_Finished = 0,
                    MiracastReceiverDisconnectReason_AppSpecificError = 1,
                    MiracastReceiverDisconnectReason_ConnectionNotAccepted = 2,
                    MiracastReceiverDisconnectReason_DisconnectedByUser = 3,
                    MiracastReceiverDisconnectReason_FailedToStartStreaming = 4,
                    MiracastReceiverDisconnectReason_MediaDecodingError = 5,
                    MiracastReceiverDisconnectReason_MediaStreamingError = 6,
                    MiracastReceiverDisconnectReason_MediaDecryptionError = 7,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverGameControllerDeviceUsageMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverGameControllerDeviceUsageMode : int
                {
                    MiracastReceiverGameControllerDeviceUsageMode_AsGameController = 0,
                    MiracastReceiverGameControllerDeviceUsageMode_AsMouseAndKeyboard = 1,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverListeningStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverListeningStatus : int
                {
                    MiracastReceiverListeningStatus_NotListening = 0,
                    MiracastReceiverListeningStatus_Listening = 1,
                    MiracastReceiverListeningStatus_ConnectionPending = 2,
                    MiracastReceiverListeningStatus_Connected = 3,
                    MiracastReceiverListeningStatus_DisabledByPolicy = 4,
                    MiracastReceiverListeningStatus_TemporarilyDisabled = 5,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverSessionStartStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverSessionStartStatus : int
                {
                    MiracastReceiverSessionStartStatus_Success = 0,
                    MiracastReceiverSessionStartStatus_UnknownFailure = 1,
                    MiracastReceiverSessionStartStatus_MiracastNotSupported = 2,
                    MiracastReceiverSessionStartStatus_AccessDenied = 3,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverWiFiStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastReceiverWiFiStatus : int
                {
                    MiracastReceiverWiFiStatus_MiracastSupportUndetermined = 0,
                    MiracastReceiverWiFiStatus_MiracastNotSupported = 1,
                    MiracastReceiverWiFiStatus_MiracastSupportNotOptimized = 2,
                    MiracastReceiverWiFiStatus_MiracastSupported = 3,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastTransmitterAuthorizationStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [v1_enum, contract] */
                enum MiracastTransmitterAuthorizationStatus : int
                {
                    MiracastTransmitterAuthorizationStatus_Undecided = 0,
                    MiracastTransmitterAuthorizationStatus_Allowed = 1,
                    MiracastTransmitterAuthorizationStatus_AlwaysPrompt = 2,
                    MiracastTransmitterAuthorizationStatus_Blocked = 3,
                };
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiver
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiver
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiver[] = L"Windows.Media.Miracast.IMiracastReceiver";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("7A315258-E444-51B4-AFF7-B88DAA1229E0"), exclusiveto, contract] */
                MIDL_INTERFACE("7A315258-E444-51B4-AFF7-B88DAA1229E0")
                IMiracastReceiver : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDefaultSettings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverSettings * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentSettings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverSettings * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentSettingsAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DisconnectAllAndApplySettings(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Miracast::IMiracastReceiverSettings * settings,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverApplySettingsResult * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DisconnectAllAndApplySettingsAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Miracast::IMiracastReceiverSettings * settings,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetStatus(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverStatus * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetStatusAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * * operation
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_StatusChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_StatusChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateSession(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Core::ICoreApplicationView * view,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverSession * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateSessionAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Core::ICoreApplicationView * view,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ClearKnownTransmitters(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RemoveKnownTransmitter(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Miracast::IMiracastTransmitter * transmitter
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiver=_uuidof(IMiracastReceiver);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverApplySettingsResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverApplySettingsResult
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult[] = L"Windows.Media.Miracast.IMiracastReceiverApplySettingsResult";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("D0AA6272-09CD-58E1-A4F2-5D5143D312F9"), exclusiveto, contract] */
                MIDL_INTERFACE("D0AA6272-09CD-58E1-A4F2-5D5143D312F9")
                IMiracastReceiverApplySettingsResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastReceiverApplySettingsStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverApplySettingsResult=_uuidof(IMiracastReceiverApplySettingsResult);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverConnection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverConnection
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverConnection[] = L"Windows.Media.Miracast.IMiracastReceiverConnection";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("704B2F36-D2E5-551F-A854-F822B7917D28"), exclusiveto, contract] */
                MIDL_INTERFACE("704B2F36-D2E5-551F-A854-F822B7917D28")
                IMiracastReceiverConnection : public IInspectable
                {
                public:
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE Disconnect(
                        /* [in] */ABI::Windows::Media::Miracast::MiracastReceiverDisconnectReason reason
                        ) = 0;
                    /* [overload] */virtual HRESULT STDMETHODCALLTYPE DisconnectWithMessage(
                        /* [in] */ABI::Windows::Media::Miracast::MiracastReceiverDisconnectReason reason,
                        /* [in] */__RPC__in HSTRING message
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Pause(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE PauseAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Resume(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE ResumeAsync(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Transmitter(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastTransmitter * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InputDevices(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverInputDevices * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CursorImageChannel(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannel * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StreamControl(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverStreamControl * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverConnection=_uuidof(IMiracastReceiverConnection);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs[] = L"Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("7D8DFA39-307A-5C0F-94BD-D0C69D169982"), exclusiveto, contract] */
                MIDL_INTERFACE("7D8DFA39-307A-5C0F-94BD-D0C69D169982")
                IMiracastReceiverConnectionCreatedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Connection(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverConnection * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Pin(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverConnectionCreatedEventArgs=_uuidof(IMiracastReceiverConnectionCreatedEventArgs);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverCursorImageChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverCursorImageChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel[] = L"Windows.Media.Miracast.IMiracastReceiverCursorImageChannel";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("D9AC332D-723A-5A9D-B90A-81153EFA2A0F"), exclusiveto, contract] */
                MIDL_INTERFACE("D9AC332D-723A-5A9D-B90A-81153EFA2A0F")
                IMiracastReceiverCursorImageChannel : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxImageSize(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::SizeInt32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Position(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::PointInt32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ImageStream(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Storage::Streams::IRandomAccessStreamWithContentType * * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ImageStreamChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ImageStreamChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_PositionChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_PositionChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverCursorImageChannel=_uuidof(IMiracastReceiverCursorImageChannel);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings[] = L"Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("CCDBEDFF-BD00-5B9C-8E4C-00CACF86B634"), exclusiveto, contract] */
                MIDL_INTERFACE("CCDBEDFF-BD00-5B9C-8E4C-00CACF86B634")
                IMiracastReceiverCursorImageChannelSettings : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsEnabled(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxImageSize(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::SizeInt32 * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MaxImageSize(
                        /* [in] */ABI::Windows::Graphics::SizeInt32 value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverCursorImageChannelSettings=_uuidof(IMiracastReceiverCursorImageChannelSettings);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverDisconnectedEventArgs[] = L"Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("D9A15E5E-5FEE-57E6-B4B0-04727DB93229"), exclusiveto, contract] */
                MIDL_INTERFACE("D9A15E5E-5FEE-57E6-B4B0-04727DB93229")
                IMiracastReceiverDisconnectedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Connection(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverConnection * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverDisconnectedEventArgs=_uuidof(IMiracastReceiverDisconnectedEventArgs);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverGameControllerDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverGameControllerDevice
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice[] = L"Windows.Media.Miracast.IMiracastReceiverGameControllerDevice";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("2D7171E8-BED4-5118-A058-E2477EB5888D"), exclusiveto, contract] */
                MIDL_INTERFACE("2D7171E8-BED4-5118-A058-E2477EB5888D")
                IMiracastReceiverGameControllerDevice : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TransmitInput(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_TransmitInput(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRequestedByTransmitter(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsTransmittingInput(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Mode(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Mode(
                        /* [in] */ABI::Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Changed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Changed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverGameControllerDevice=_uuidof(IMiracastReceiverGameControllerDevice);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverInputDevices
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverInputDevices
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverInputDevices[] = L"Windows.Media.Miracast.IMiracastReceiverInputDevices";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("DA35BB02-28AA-5EE8-96F5-A42901C66F00"), exclusiveto, contract] */
                MIDL_INTERFACE("DA35BB02-28AA-5EE8-96F5-A42901C66F00")
                IMiracastReceiverInputDevices : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Keyboard(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverKeyboardDevice * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_GameController(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverGameControllerDevice * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverInputDevices=_uuidof(IMiracastReceiverInputDevices);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverKeyboardDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverKeyboardDevice
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice[] = L"Windows.Media.Miracast.IMiracastReceiverKeyboardDevice";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("BEB67272-06C0-54FF-AC96-217464FF2501"), exclusiveto, contract] */
                MIDL_INTERFACE("BEB67272-06C0-54FF-AC96-217464FF2501")
                IMiracastReceiverKeyboardDevice : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TransmitInput(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_TransmitInput(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRequestedByTransmitter(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsTransmittingInput(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Changed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Changed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverKeyboardDevice=_uuidof(IMiracastReceiverKeyboardDevice);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs[] = L"Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("17CF519E-1246-531D-945A-6B158E39C3AA"), exclusiveto, contract] */
                MIDL_INTERFACE("17CF519E-1246-531D-945A-6B158E39C3AA")
                IMiracastReceiverMediaSourceCreatedEventArgs : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Connection(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverConnection * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MediaSource(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Core::IMediaSource2 * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CursorImageChannelSettings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverMediaSourceCreatedEventArgs=_uuidof(IMiracastReceiverMediaSourceCreatedEventArgs);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverSession[] = L"Windows.Media.Miracast.IMiracastReceiverSession";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("1D2BCDB4-EF8B-5209-BFC9-C32116504803"), exclusiveto, contract] */
                MIDL_INTERFACE("1D2BCDB4-EF8B-5209-BFC9-C32116504803")
                IMiracastReceiverSession : public IInspectable
                {
                public:
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ConnectionCreated(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ConnectionCreated(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_MediaSourceCreated(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_MediaSourceCreated(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Disconnected(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Disconnected(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AllowConnectionTakeover(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AllowConnectionTakeover(
                        /* [in] */::boolean value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxSimultaneousConnections(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MaxSimultaneousConnections(
                        /* [in] */INT32 value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE Start(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverSessionStartResult * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE StartAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverSession=_uuidof(IMiracastReceiverSession);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverSessionStartResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverSessionStartResult
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverSessionStartResult[] = L"Windows.Media.Miracast.IMiracastReceiverSessionStartResult";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("B7C573EE-40CA-51FF-95F2-C9DE34F2E90E"), exclusiveto, contract] */
                MIDL_INTERFACE("B7C573EE-40CA-51FF-95F2-C9DE34F2E90E")
                IMiracastReceiverSessionStartResult : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Status(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastReceiverSessionStartStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverSessionStartResult=_uuidof(IMiracastReceiverSessionStartResult);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverSettings[] = L"Windows.Media.Miracast.IMiracastReceiverSettings";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("57CD2F24-C55A-5FBE-9464-EB05307705DD"), exclusiveto, contract] */
                MIDL_INTERFACE("57CD2F24-C55A-5FBE-9464-EB05307705DD")
                IMiracastReceiverSettings : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_FriendlyName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_FriendlyName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ModelName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ModelName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ModelNumber(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ModelNumber(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AuthorizationMethod(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AuthorizationMethod(
                        /* [in] */ABI::Windows::Media::Miracast::MiracastReceiverAuthorizationMethod value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequireAuthorizationFromKnownTransmitters(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RequireAuthorizationFromKnownTransmitters(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverSettings=_uuidof(IMiracastReceiverSettings);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverStatus
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverStatus[] = L"Windows.Media.Miracast.IMiracastReceiverStatus";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("C28A5591-23AB-519E-AD09-90BFF6DCC87E"), exclusiveto, contract] */
                MIDL_INTERFACE("C28A5591-23AB-519E-AD09-90BFF6DCC87E")
                IMiracastReceiverStatus : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ListeningStatus(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastReceiverListeningStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WiFiStatus(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastReceiverWiFiStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsConnectionTakeoverSupported(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxSimultaneousConnections(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_KnownTransmitters(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverStatus=_uuidof(IMiracastReceiverStatus);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverStreamControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverStreamControl
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverStreamControl[] = L"Windows.Media.Miracast.IMiracastReceiverStreamControl";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("38EA2D8B-2769-5AD7-8A8A-254B9DF7BA82"), exclusiveto, contract] */
                MIDL_INTERFACE("38EA2D8B-2769-5AD7-8A8A-254B9DF7BA82")
                IMiracastReceiverStreamControl : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetVideoStreamSettings(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetVideoStreamSettingsAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SuggestVideoStreamSettings(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings * settings
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SuggestVideoStreamSettingsAsync(
                        /* [in] */__RPC__in_opt ABI::Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings * settings,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IAsyncAction * * operation
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MuteAudio(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MuteAudio(
                        /* [in] */::boolean value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverStreamControl=_uuidof(IMiracastReceiverStreamControl);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverVideoStreamSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings[] = L"Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("169B5E1B-149D-52D0-B126-6F89744E4F50"), exclusiveto, contract] */
                MIDL_INTERFACE("169B5E1B-149D-52D0-B126-6F89744E4F50")
                IMiracastReceiverVideoStreamSettings : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Size(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::SizeInt32 * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Size(
                        /* [in] */ABI::Windows::Graphics::SizeInt32 value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Bitrate(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Bitrate(
                        /* [in] */INT32 value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastReceiverVideoStreamSettings=_uuidof(IMiracastReceiverVideoStreamSettings);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastTransmitter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastTransmitter
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastTransmitter[] = L"Windows.Media.Miracast.IMiracastTransmitter";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Miracast {
                /* [object, uuid("342D79FD-2E64-5508-8A30-833D1EAC70D0"), exclusiveto, contract] */
                MIDL_INTERFACE("342D79FD-2E64-5508-8A30-833D1EAC70D0")
                IMiracastTransmitter : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Name(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Name(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AuthorizationStatus(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus * value
                        ) = 0;
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AuthorizationStatus(
                        /* [in] */ABI::Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetConnections(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MacAddress(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LastConnectionTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IMiracastTransmitter=_uuidof(IMiracastTransmitter);
                
            } /* Miracast */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiver
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiver ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiver_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiver_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiver[] = L"Windows.Media.Miracast.MiracastReceiver";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverApplySettingsResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverApplySettingsResult ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverApplySettingsResult_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverApplySettingsResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverApplySettingsResult[] = L"Windows.Media.Miracast.MiracastReceiverApplySettingsResult";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverConnection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverConnection ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnection_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverConnection[] = L"Windows.Media.Miracast.MiracastReceiverConnection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnectionCreatedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnectionCreatedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverConnectionCreatedEventArgs[] = L"Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverCursorImageChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverCursorImageChannel ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannel_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannel_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverCursorImageChannel[] = L"Windows.Media.Miracast.MiracastReceiverCursorImageChannel";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannelSettings_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannelSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverCursorImageChannelSettings[] = L"Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverDisconnectedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverDisconnectedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverDisconnectedEventArgs[] = L"Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverGameControllerDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverGameControllerDevice ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverGameControllerDevice_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverGameControllerDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverGameControllerDevice[] = L"Windows.Media.Miracast.MiracastReceiverGameControllerDevice";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverInputDevices
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverInputDevices ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverInputDevices_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverInputDevices_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverInputDevices[] = L"Windows.Media.Miracast.MiracastReceiverInputDevices";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverKeyboardDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverKeyboardDevice ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverKeyboardDevice_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverKeyboardDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverKeyboardDevice[] = L"Windows.Media.Miracast.MiracastReceiverKeyboardDevice";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverMediaSourceCreatedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverMediaSourceCreatedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverMediaSourceCreatedEventArgs[] = L"Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSession_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverSession[] = L"Windows.Media.Miracast.MiracastReceiverSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverSessionStartResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverSessionStartResult ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSessionStartResult_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSessionStartResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverSessionStartResult[] = L"Windows.Media.Miracast.MiracastReceiverSessionStartResult";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSettings_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverSettings[] = L"Windows.Media.Miracast.MiracastReceiverSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverStatus ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStatus_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStatus_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverStatus[] = L"Windows.Media.Miracast.MiracastReceiverStatus";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverStreamControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverStreamControl ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStreamControl_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStreamControl_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverStreamControl[] = L"Windows.Media.Miracast.MiracastReceiverStreamControl";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverVideoStreamSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverVideoStreamSettings_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverVideoStreamSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverVideoStreamSettings[] = L"Windows.Media.Miracast.MiracastReceiverVideoStreamSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastTransmitter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastTransmitter ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastTransmitter_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastTransmitter_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastTransmitter[] = L"Windows.Media.Miracast.MiracastTransmitter";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter;

#endif // ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection;

typedef struct __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl;

interface __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection
{
    CONST_VTBL struct __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection;

typedef  struct __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection **first);

    END_INTERFACE
} __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl;

interface __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection
{
    CONST_VTBL struct __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter;

typedef struct __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl;

interface __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter
{
    CONST_VTBL struct __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter;

typedef  struct __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CMedia__CMiracast__CMiracastTransmitter **first);

    END_INTERFACE
} __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl;

interface __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter
{
    CONST_VTBL struct __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection;

typedef struct __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
            /* [in] */ __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl;

interface __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection
{
    CONST_VTBL struct __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnectionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter;

typedef struct __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
            /* [in] */ __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl;

interface __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter
{
    CONST_VTBL struct __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitterVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResultVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSession **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResultVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResultVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResultVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettingsVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettingsVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettingsVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatusVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatusVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatusVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettingsVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettingsVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettingsVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#ifndef ____x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView __x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView;

#endif // ____x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView_FWD_DEFINED__






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






typedef struct __x_ABI_CWindows_CGraphics_CPointInt32 __x_ABI_CWindows_CGraphics_CPointInt32;


typedef struct __x_ABI_CWindows_CGraphics_CSizeInt32 __x_ABI_CWindows_CGraphics_CSizeInt32;



#ifndef ____x_ABI_CWindows_CMedia_CCore_CIMediaSource2_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CCore_CIMediaSource2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CCore_CIMediaSource2 __x_ABI_CWindows_CMedia_CCore_CIMediaSource2;

#endif // ____x_ABI_CWindows_CMedia_CCore_CIMediaSource2_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverApplySettingsStatus __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverApplySettingsStatus;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverAuthorizationMethod __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverAuthorizationMethod;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverDisconnectReason __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverDisconnectReason;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverGameControllerDeviceUsageMode __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverGameControllerDeviceUsageMode;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverListeningStatus __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverListeningStatus;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverSessionStartStatus __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverSessionStartStatus;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverWiFiStatus __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverWiFiStatus;


typedef enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastTransmitterAuthorizationStatus __x_ABI_CWindows_CMedia_CMiracast_CMiracastTransmitterAuthorizationStatus;













































/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverApplySettingsStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverApplySettingsStatus
{
    MiracastReceiverApplySettingsStatus_Success = 0,
    MiracastReceiverApplySettingsStatus_UnknownFailure = 1,
    MiracastReceiverApplySettingsStatus_MiracastNotSupported = 2,
    MiracastReceiverApplySettingsStatus_AccessDenied = 3,
    MiracastReceiverApplySettingsStatus_FriendlyNameTooLong = 4,
    MiracastReceiverApplySettingsStatus_ModelNameTooLong = 5,
    MiracastReceiverApplySettingsStatus_ModelNumberTooLong = 6,
    MiracastReceiverApplySettingsStatus_InvalidSettings = 7,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverAuthorizationMethod
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverAuthorizationMethod
{
    MiracastReceiverAuthorizationMethod_None = 0,
    MiracastReceiverAuthorizationMethod_ConfirmConnection = 1,
    MiracastReceiverAuthorizationMethod_PinDisplayIfRequested = 2,
    MiracastReceiverAuthorizationMethod_PinDisplayRequired = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverDisconnectReason
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverDisconnectReason
{
    MiracastReceiverDisconnectReason_Finished = 0,
    MiracastReceiverDisconnectReason_AppSpecificError = 1,
    MiracastReceiverDisconnectReason_ConnectionNotAccepted = 2,
    MiracastReceiverDisconnectReason_DisconnectedByUser = 3,
    MiracastReceiverDisconnectReason_FailedToStartStreaming = 4,
    MiracastReceiverDisconnectReason_MediaDecodingError = 5,
    MiracastReceiverDisconnectReason_MediaStreamingError = 6,
    MiracastReceiverDisconnectReason_MediaDecryptionError = 7,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverGameControllerDeviceUsageMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverGameControllerDeviceUsageMode
{
    MiracastReceiverGameControllerDeviceUsageMode_AsGameController = 0,
    MiracastReceiverGameControllerDeviceUsageMode_AsMouseAndKeyboard = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverListeningStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverListeningStatus
{
    MiracastReceiverListeningStatus_NotListening = 0,
    MiracastReceiverListeningStatus_Listening = 1,
    MiracastReceiverListeningStatus_ConnectionPending = 2,
    MiracastReceiverListeningStatus_Connected = 3,
    MiracastReceiverListeningStatus_DisabledByPolicy = 4,
    MiracastReceiverListeningStatus_TemporarilyDisabled = 5,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverSessionStartStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverSessionStartStatus
{
    MiracastReceiverSessionStartStatus_Success = 0,
    MiracastReceiverSessionStartStatus_UnknownFailure = 1,
    MiracastReceiverSessionStartStatus_MiracastNotSupported = 2,
    MiracastReceiverSessionStartStatus_AccessDenied = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastReceiverWiFiStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverWiFiStatus
{
    MiracastReceiverWiFiStatus_MiracastSupportUndetermined = 0,
    MiracastReceiverWiFiStatus_MiracastNotSupported = 1,
    MiracastReceiverWiFiStatus_MiracastSupportNotOptimized = 2,
    MiracastReceiverWiFiStatus_MiracastSupported = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.Media.Miracast.MiracastTransmitterAuthorizationStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CMiracast_CMiracastTransmitterAuthorizationStatus
{
    MiracastTransmitterAuthorizationStatus_Undecided = 0,
    MiracastTransmitterAuthorizationStatus_Allowed = 1,
    MiracastTransmitterAuthorizationStatus_AlwaysPrompt = 2,
    MiracastTransmitterAuthorizationStatus_Blocked = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiver
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiver
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiver[] = L"Windows.Media.Miracast.IMiracastReceiver";
/* [object, uuid("7A315258-E444-51B4-AFF7-B88DAA1229E0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDefaultSettings )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetCurrentSettings )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetCurrentSettingsAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSettings * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *DisconnectAllAndApplySettings )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * settings,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * * result
        );
    HRESULT ( STDMETHODCALLTYPE *DisconnectAllAndApplySettingsAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * settings,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverApplySettingsResult * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetStatus )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetStatusAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverStatus * * operation
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_StatusChanged )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiver_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_StatusChanged )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *CreateSession )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView * view,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateSessionAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CCore_CICoreApplicationView * view,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSession * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *ClearKnownTransmitters )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This
        );
    HRESULT ( STDMETHODCALLTYPE *RemoveKnownTransmitter )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * transmitter
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetDefaultSettings(This,result) \
    ( (This)->lpVtbl->GetDefaultSettings(This,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetCurrentSettings(This,result) \
    ( (This)->lpVtbl->GetCurrentSettings(This,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetCurrentSettingsAsync(This,operation) \
    ( (This)->lpVtbl->GetCurrentSettingsAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_DisconnectAllAndApplySettings(This,settings,result) \
    ( (This)->lpVtbl->DisconnectAllAndApplySettings(This,settings,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_DisconnectAllAndApplySettingsAsync(This,settings,operation) \
    ( (This)->lpVtbl->DisconnectAllAndApplySettingsAsync(This,settings,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetStatus(This,result) \
    ( (This)->lpVtbl->GetStatus(This,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_GetStatusAsync(This,operation) \
    ( (This)->lpVtbl->GetStatusAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_add_StatusChanged(This,handler,token) \
    ( (This)->lpVtbl->add_StatusChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_remove_StatusChanged(This,token) \
    ( (This)->lpVtbl->remove_StatusChanged(This,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_CreateSession(This,view,result) \
    ( (This)->lpVtbl->CreateSession(This,view,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_CreateSessionAsync(This,view,operation) \
    ( (This)->lpVtbl->CreateSessionAsync(This,view,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_ClearKnownTransmitters(This) \
    ( (This)->lpVtbl->ClearKnownTransmitters(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_RemoveKnownTransmitter(This,transmitter) \
    ( (This)->lpVtbl->RemoveKnownTransmitter(This,transmitter) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiver_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverApplySettingsResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverApplySettingsResult
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult[] = L"Windows.Media.Miracast.IMiracastReceiverApplySettingsResult";
/* [object, uuid("D0AA6272-09CD-58E1-A4F2-5D5143D312F9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverApplySettingsStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResultVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverApplySettingsResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverConnection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverConnection
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverConnection[] = L"Windows.Media.Miracast.IMiracastReceiverConnection";
/* [object, uuid("704B2F36-D2E5-551F-A854-F822B7917D28"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *Disconnect )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [in] */__x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverDisconnectReason reason
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *DisconnectWithMessage )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [in] */__x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverDisconnectReason reason,
        /* [in] */__RPC__in HSTRING message
        );
    HRESULT ( STDMETHODCALLTYPE *Pause )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This
        );
    HRESULT ( STDMETHODCALLTYPE *PauseAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *Resume )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This
        );
    HRESULT ( STDMETHODCALLTYPE *ResumeAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Transmitter )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InputDevices )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CursorImageChannel )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StreamControl )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_Disconnect(This,reason) \
    ( (This)->lpVtbl->Disconnect(This,reason) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_DisconnectWithMessage(This,reason,message) \
    ( (This)->lpVtbl->DisconnectWithMessage(This,reason,message) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_Pause(This) \
    ( (This)->lpVtbl->Pause(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_PauseAsync(This,operation) \
    ( (This)->lpVtbl->PauseAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_Resume(This) \
    ( (This)->lpVtbl->Resume(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_ResumeAsync(This,operation) \
    ( (This)->lpVtbl->ResumeAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_get_Transmitter(This,value) \
    ( (This)->lpVtbl->get_Transmitter(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_get_InputDevices(This,value) \
    ( (This)->lpVtbl->get_InputDevices(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_get_CursorImageChannel(This,value) \
    ( (This)->lpVtbl->get_CursorImageChannel(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_get_StreamControl(This,value) \
    ( (This)->lpVtbl->get_StreamControl(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs[] = L"Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs";
/* [object, uuid("7D8DFA39-307A-5C0F-94BD-D0C69D169982"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Connection )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Pin )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_get_Connection(This,value) \
    ( (This)->lpVtbl->get_Connection(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_get_Pin(This,value) \
    ( (This)->lpVtbl->get_Pin(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_GetDeferral(This,result) \
    ( (This)->lpVtbl->GetDeferral(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnectionCreatedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverCursorImageChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverCursorImageChannel
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel[] = L"Windows.Media.Miracast.IMiracastReceiverCursorImageChannel";
/* [object, uuid("D9AC332D-723A-5A9D-B90A-81153EFA2A0F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsEnabled )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxImageSize )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CSizeInt32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Position )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CPointInt32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ImageStream )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamWithContentType * * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ImageStreamChanged )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ImageStreamChanged )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_PositionChanged )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverCursorImageChannel_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_PositionChanged )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_get_IsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_get_MaxImageSize(This,value) \
    ( (This)->lpVtbl->get_MaxImageSize(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_get_Position(This,value) \
    ( (This)->lpVtbl->get_Position(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_get_ImageStream(This,value) \
    ( (This)->lpVtbl->get_ImageStream(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_add_ImageStreamChanged(This,handler,token) \
    ( (This)->lpVtbl->add_ImageStreamChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_remove_ImageStreamChanged(This,token) \
    ( (This)->lpVtbl->remove_ImageStreamChanged(This,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_add_PositionChanged(This,handler,token) \
    ( (This)->lpVtbl->add_PositionChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_remove_PositionChanged(This,token) \
    ( (This)->lpVtbl->remove_PositionChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannel_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings[] = L"Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings";
/* [object, uuid("CCDBEDFF-BD00-5B9C-8E4C-00CACF86B634"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsEnabled )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsEnabled )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxImageSize )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CSizeInt32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MaxImageSize )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CSizeInt32 value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettingsVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_get_IsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_put_IsEnabled(This,value) \
    ( (This)->lpVtbl->put_IsEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_get_MaxImageSize(This,value) \
    ( (This)->lpVtbl->get_MaxImageSize(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_put_MaxImageSize(This,value) \
    ( (This)->lpVtbl->put_MaxImageSize(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverDisconnectedEventArgs[] = L"Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs";
/* [object, uuid("D9A15E5E-5FEE-57E6-B4B0-04727DB93229"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Connection )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_get_Connection(This,value) \
    ( (This)->lpVtbl->get_Connection(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverDisconnectedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverGameControllerDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverGameControllerDevice
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice[] = L"Windows.Media.Miracast.IMiracastReceiverGameControllerDevice";
/* [object, uuid("2D7171E8-BED4-5118-A058-E2477EB5888D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDeviceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TransmitInput )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_TransmitInput )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRequestedByTransmitter )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsTransmittingInput )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Mode )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverGameControllerDeviceUsageMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Mode )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [in] */__x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverGameControllerDeviceUsageMode value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Changed )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverGameControllerDevice_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Changed )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDeviceVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDeviceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_get_TransmitInput(This,value) \
    ( (This)->lpVtbl->get_TransmitInput(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_put_TransmitInput(This,value) \
    ( (This)->lpVtbl->put_TransmitInput(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_get_IsRequestedByTransmitter(This,value) \
    ( (This)->lpVtbl->get_IsRequestedByTransmitter(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_get_IsTransmittingInput(This,value) \
    ( (This)->lpVtbl->get_IsTransmittingInput(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_get_Mode(This,value) \
    ( (This)->lpVtbl->get_Mode(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_put_Mode(This,value) \
    ( (This)->lpVtbl->put_Mode(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_add_Changed(This,handler,token) \
    ( (This)->lpVtbl->add_Changed(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_remove_Changed(This,token) \
    ( (This)->lpVtbl->remove_Changed(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverInputDevices
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverInputDevices
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverInputDevices[] = L"Windows.Media.Miracast.IMiracastReceiverInputDevices";
/* [object, uuid("DA35BB02-28AA-5EE8-96F5-A42901C66F00"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevicesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Keyboard )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_GameController )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverGameControllerDevice * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevicesVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevicesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_get_Keyboard(This,value) \
    ( (This)->lpVtbl->get_Keyboard(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_get_GameController(This,value) \
    ( (This)->lpVtbl->get_GameController(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverInputDevices_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverKeyboardDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverKeyboardDevice
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice[] = L"Windows.Media.Miracast.IMiracastReceiverKeyboardDevice";
/* [object, uuid("BEB67272-06C0-54FF-AC96-217464FF2501"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDeviceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TransmitInput )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_TransmitInput )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRequestedByTransmitter )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsTransmittingInput )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Changed )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverKeyboardDevice_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Changed )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDeviceVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDeviceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_get_TransmitInput(This,value) \
    ( (This)->lpVtbl->get_TransmitInput(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_put_TransmitInput(This,value) \
    ( (This)->lpVtbl->put_TransmitInput(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_get_IsRequestedByTransmitter(This,value) \
    ( (This)->lpVtbl->get_IsRequestedByTransmitter(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_get_IsTransmittingInput(This,value) \
    ( (This)->lpVtbl->get_IsTransmittingInput(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_add_Changed(This,handler,token) \
    ( (This)->lpVtbl->add_Changed(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_remove_Changed(This,token) \
    ( (This)->lpVtbl->remove_Changed(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverKeyboardDevice_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs[] = L"Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs";
/* [object, uuid("17CF519E-1246-531D-945A-6B158E39C3AA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Connection )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverConnection * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MediaSource )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CCore_CIMediaSource2 * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CursorImageChannelSettings )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverCursorImageChannelSettings * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_get_Connection(This,value) \
    ( (This)->lpVtbl->get_Connection(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_get_MediaSource(This,value) \
    ( (This)->lpVtbl->get_MediaSource(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_get_CursorImageChannelSettings(This,value) \
    ( (This)->lpVtbl->get_CursorImageChannelSettings(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_GetDeferral(This,result) \
    ( (This)->lpVtbl->GetDeferral(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverMediaSourceCreatedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverSession[] = L"Windows.Media.Miracast.IMiracastReceiverSession";
/* [object, uuid("1D2BCDB4-EF8B-5209-BFC9-C32116504803"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ConnectionCreated )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverConnectionCreatedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ConnectionCreated )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_MediaSourceCreated )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverMediaSourceCreatedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_MediaSourceCreated )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Disconnected )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CMiracast__CMiracastReceiverSession_Windows__CMedia__CMiracast__CMiracastReceiverDisconnectedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Disconnected )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AllowConnectionTakeover )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AllowConnectionTakeover )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxSimultaneousConnections )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MaxSimultaneousConnections )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [in] */INT32 value
        );
    HRESULT ( STDMETHODCALLTYPE *Start )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * * result
        );
    HRESULT ( STDMETHODCALLTYPE *StartAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverSessionStartResult * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_add_ConnectionCreated(This,handler,token) \
    ( (This)->lpVtbl->add_ConnectionCreated(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_remove_ConnectionCreated(This,token) \
    ( (This)->lpVtbl->remove_ConnectionCreated(This,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_add_MediaSourceCreated(This,handler,token) \
    ( (This)->lpVtbl->add_MediaSourceCreated(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_remove_MediaSourceCreated(This,token) \
    ( (This)->lpVtbl->remove_MediaSourceCreated(This,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_add_Disconnected(This,handler,token) \
    ( (This)->lpVtbl->add_Disconnected(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_remove_Disconnected(This,token) \
    ( (This)->lpVtbl->remove_Disconnected(This,token) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_get_AllowConnectionTakeover(This,value) \
    ( (This)->lpVtbl->get_AllowConnectionTakeover(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_put_AllowConnectionTakeover(This,value) \
    ( (This)->lpVtbl->put_AllowConnectionTakeover(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_get_MaxSimultaneousConnections(This,value) \
    ( (This)->lpVtbl->get_MaxSimultaneousConnections(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_put_MaxSimultaneousConnections(This,value) \
    ( (This)->lpVtbl->put_MaxSimultaneousConnections(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_Start(This,result) \
    ( (This)->lpVtbl->Start(This,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_StartAsync(This,operation) \
    ( (This)->lpVtbl->StartAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverSessionStartResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverSessionStartResult
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverSessionStartResult[] = L"Windows.Media.Miracast.IMiracastReceiverSessionStartResult";
/* [object, uuid("B7C573EE-40CA-51FF-95F2-C9DE34F2E90E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResultVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Status )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverSessionStartStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResultVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResultVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_get_Status(This,value) \
    ( (This)->lpVtbl->get_Status(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSessionStartResult_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverSettings[] = L"Windows.Media.Miracast.IMiracastReceiverSettings";
/* [object, uuid("57CD2F24-C55A-5FBE-9464-EB05307705DD"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_FriendlyName )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_FriendlyName )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ModelName )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ModelName )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ModelNumber )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ModelNumber )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AuthorizationMethod )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverAuthorizationMethod * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AuthorizationMethod )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [in] */__x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverAuthorizationMethod value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequireAuthorizationFromKnownTransmitters )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RequireAuthorizationFromKnownTransmitters )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettingsVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_get_FriendlyName(This,value) \
    ( (This)->lpVtbl->get_FriendlyName(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_put_FriendlyName(This,value) \
    ( (This)->lpVtbl->put_FriendlyName(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_get_ModelName(This,value) \
    ( (This)->lpVtbl->get_ModelName(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_put_ModelName(This,value) \
    ( (This)->lpVtbl->put_ModelName(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_get_ModelNumber(This,value) \
    ( (This)->lpVtbl->get_ModelNumber(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_put_ModelNumber(This,value) \
    ( (This)->lpVtbl->put_ModelNumber(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_get_AuthorizationMethod(This,value) \
    ( (This)->lpVtbl->get_AuthorizationMethod(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_put_AuthorizationMethod(This,value) \
    ( (This)->lpVtbl->put_AuthorizationMethod(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_get_RequireAuthorizationFromKnownTransmitters(This,value) \
    ( (This)->lpVtbl->get_RequireAuthorizationFromKnownTransmitters(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_put_RequireAuthorizationFromKnownTransmitters(This,value) \
    ( (This)->lpVtbl->put_RequireAuthorizationFromKnownTransmitters(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverStatus
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverStatus[] = L"Windows.Media.Miracast.IMiracastReceiverStatus";
/* [object, uuid("C28A5591-23AB-519E-AD09-90BFF6DCC87E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatusVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ListeningStatus )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverListeningStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WiFiStatus )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastReceiverWiFiStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsConnectionTakeoverSupported )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxSimultaneousConnections )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_KnownTransmitters )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastTransmitter * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatusVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatusVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_get_ListeningStatus(This,value) \
    ( (This)->lpVtbl->get_ListeningStatus(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_get_WiFiStatus(This,value) \
    ( (This)->lpVtbl->get_WiFiStatus(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_get_IsConnectionTakeoverSupported(This,value) \
    ( (This)->lpVtbl->get_IsConnectionTakeoverSupported(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_get_MaxSimultaneousConnections(This,value) \
    ( (This)->lpVtbl->get_MaxSimultaneousConnections(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_get_KnownTransmitters(This,value) \
    ( (This)->lpVtbl->get_KnownTransmitters(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStatus_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverStreamControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverStreamControl
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverStreamControl[] = L"Windows.Media.Miracast.IMiracastReceiverStreamControl";
/* [object, uuid("38EA2D8B-2769-5AD7-8A8A-254B9DF7BA82"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControlVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetVideoStreamSettings )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetVideoStreamSettingsAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CMiracast__CMiracastReceiverVideoStreamSettings * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *SuggestVideoStreamSettings )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * settings
        );
    HRESULT ( STDMETHODCALLTYPE *SuggestVideoStreamSettingsAsync )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * settings,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIAsyncAction * * operation
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MuteAudio )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MuteAudio )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControlVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControlVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_GetVideoStreamSettings(This,result) \
    ( (This)->lpVtbl->GetVideoStreamSettings(This,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_GetVideoStreamSettingsAsync(This,operation) \
    ( (This)->lpVtbl->GetVideoStreamSettingsAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_SuggestVideoStreamSettings(This,settings) \
    ( (This)->lpVtbl->SuggestVideoStreamSettings(This,settings) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_SuggestVideoStreamSettingsAsync(This,settings,operation) \
    ( (This)->lpVtbl->SuggestVideoStreamSettingsAsync(This,settings,operation) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_get_MuteAudio(This,value) \
    ( (This)->lpVtbl->get_MuteAudio(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_put_MuteAudio(This,value) \
    ( (This)->lpVtbl->put_MuteAudio(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverStreamControl_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastReceiverVideoStreamSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings[] = L"Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings";
/* [object, uuid("169B5E1B-149D-52D0-B126-6F89744E4F50"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Size )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CSizeInt32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Size )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CSizeInt32 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Bitrate )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Bitrate )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings * This,
        /* [in] */INT32 value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettingsVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_get_Size(This,value) \
    ( (This)->lpVtbl->get_Size(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_put_Size(This,value) \
    ( (This)->lpVtbl->put_Size(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_get_Bitrate(This,value) \
    ( (This)->lpVtbl->get_Bitrate(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_put_Bitrate(This,value) \
    ( (This)->lpVtbl->put_Bitrate(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastReceiverVideoStreamSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Media.Miracast.IMiracastTransmitter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Miracast.MiracastTransmitter
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Miracast_IMiracastTransmitter[] = L"Windows.Media.Miracast.IMiracastTransmitter";
/* [object, uuid("342D79FD-2E64-5508-8A30-833D1EAC70D0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitterVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Name )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Name )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AuthorizationStatus )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CMiracast_CMiracastTransmitterAuthorizationStatus * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AuthorizationStatus )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [in] */__x_ABI_CWindows_CMedia_CMiracast_CMiracastTransmitterAuthorizationStatus value
        );
    HRESULT ( STDMETHODCALLTYPE *GetConnections )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CMedia__CMiracast__CMiracastReceiverConnection * * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MacAddress )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LastConnectionTime )(
        __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitterVtbl;

interface __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitterVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_get_Name(This,value) \
    ( (This)->lpVtbl->get_Name(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_put_Name(This,value) \
    ( (This)->lpVtbl->put_Name(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_get_AuthorizationStatus(This,value) \
    ( (This)->lpVtbl->get_AuthorizationStatus(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_put_AuthorizationStatus(This,value) \
    ( (This)->lpVtbl->put_AuthorizationStatus(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_GetConnections(This,result) \
    ( (This)->lpVtbl->GetConnections(This,result) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_get_MacAddress(This,value) \
    ( (This)->lpVtbl->get_MacAddress(This,value) )

#define __x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_get_LastConnectionTime(This,value) \
    ( (This)->lpVtbl->get_LastConnectionTime(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter;
#endif /* !defined(____x_ABI_CWindows_CMedia_CMiracast_CIMiracastTransmitter_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiver
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiver ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiver_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiver_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiver[] = L"Windows.Media.Miracast.MiracastReceiver";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverApplySettingsResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverApplySettingsResult ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverApplySettingsResult_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverApplySettingsResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverApplySettingsResult[] = L"Windows.Media.Miracast.MiracastReceiverApplySettingsResult";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverConnection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverConnection ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnection_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverConnection[] = L"Windows.Media.Miracast.MiracastReceiverConnection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnectionCreatedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverConnectionCreatedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverConnectionCreatedEventArgs[] = L"Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverCursorImageChannel
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverCursorImageChannel ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannel_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannel_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverCursorImageChannel[] = L"Windows.Media.Miracast.MiracastReceiverCursorImageChannel";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannelSettings_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverCursorImageChannelSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverCursorImageChannelSettings[] = L"Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverDisconnectedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverDisconnectedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverDisconnectedEventArgs[] = L"Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverGameControllerDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverGameControllerDevice ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverGameControllerDevice_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverGameControllerDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverGameControllerDevice[] = L"Windows.Media.Miracast.MiracastReceiverGameControllerDevice";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverInputDevices
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverInputDevices ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverInputDevices_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverInputDevices_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverInputDevices[] = L"Windows.Media.Miracast.MiracastReceiverInputDevices";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverKeyboardDevice
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverKeyboardDevice ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverKeyboardDevice_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverKeyboardDevice_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverKeyboardDevice[] = L"Windows.Media.Miracast.MiracastReceiverKeyboardDevice";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverMediaSourceCreatedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverMediaSourceCreatedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverMediaSourceCreatedEventArgs[] = L"Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSession_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverSession[] = L"Windows.Media.Miracast.MiracastReceiverSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverSessionStartResult
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverSessionStartResult ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSessionStartResult_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSessionStartResult_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverSessionStartResult[] = L"Windows.Media.Miracast.MiracastReceiverSessionStartResult";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSettings_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverSettings[] = L"Windows.Media.Miracast.MiracastReceiverSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverStatus ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStatus_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStatus_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverStatus[] = L"Windows.Media.Miracast.MiracastReceiverStatus";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverStreamControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverStreamControl ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStreamControl_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverStreamControl_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverStreamControl[] = L"Windows.Media.Miracast.MiracastReceiverStreamControl";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastReceiverVideoStreamSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverVideoStreamSettings_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastReceiverVideoStreamSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastReceiverVideoStreamSettings[] = L"Windows.Media.Miracast.MiracastReceiverVideoStreamSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Media.Miracast.MiracastTransmitter
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Miracast.IMiracastTransmitter ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Media_Miracast_MiracastTransmitter_DEFINED
#define RUNTIMECLASS_Windows_Media_Miracast_MiracastTransmitter_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Miracast_MiracastTransmitter[] = L"Windows.Media.Miracast.MiracastTransmitter";
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
#endif // __windows2Emedia2Emiracast_p_h__

#endif // __windows2Emedia2Emiracast_h__
