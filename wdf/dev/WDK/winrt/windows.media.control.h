/* Header file automatically generated from windows.media.control.idl */
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
#ifndef __windows2Emedia2Econtrol_h__
#define __windows2Emedia2Econtrol_h__
#ifndef __windows2Emedia2Econtrol_p_h__
#define __windows2Emedia2Econtrol_p_h__


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
#include "Windows.Media.h"
#include "Windows.Storage.Streams.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface ICurrentSessionChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs ABI::Windows::Media::Control::ICurrentSessionChangedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSession;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSessionManager;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSessionManagerStatics;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSessionMediaProperties;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSessionPlaybackControls;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSessionPlaybackInfo;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IGlobalSystemMediaTransportControlsSessionTimelineProperties;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IMediaPropertiesChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs ABI::Windows::Media::Control::IMediaPropertiesChangedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface IPlaybackInfoChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs ABI::Windows::Media::Control::IPlaybackInfoChangedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface ISessionsChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs ABI::Windows::Media::Control::ISessionsChangedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                interface ITimelinePropertiesChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs ABI::Windows::Media::Control::ITimelinePropertiesChangedEventArgs

#endif // ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class GlobalSystemMediaTransportControlsSession;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE
#define DEF___FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("ec2e1c43-67db-5985-b2fa-91fd6a9c1ebf"))
IIterator<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*> __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t;
#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>
//#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE
#define DEF___FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6c594bfe-b3dd-5f1d-a78f-3a2d9e937ca3"))
IIterable<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*> __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t;
#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>
//#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE
#define DEF___FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("9b2672da-5088-5a1d-acd9-a3fc5ef1cfa4"))
IVectorView<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSession>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*> __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t;
#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>
//#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class GlobalSystemMediaTransportControlsSessionManager;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("10f0074e-923d-5510-8f4a-dde37754ca0e"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3eec115e-7346-5c27-8c5f-da78514a277b"))
IAsyncOperation<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*> __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_t;
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>
//#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class GlobalSystemMediaTransportControlsSessionMediaProperties;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("84593a3d-951a-55b6-8353-5205e577797b"))
IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties*> __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_USE
#define DEF___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b185e6f3-e0d8-51cb-913f-c98d48c93c46"))
IAsyncOperation<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties*> __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_t;
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties*>
//#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class MediaPropertiesChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("0f2ce2b7-afa7-5ed0-8cb6-8c40cf9b3a5f"))
ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::MediaPropertiesChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::MediaPropertiesChangedEventArgs*, ABI::Windows::Media::Control::IMediaPropertiesChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Control.GlobalSystemMediaTransportControlsSession, Windows.Media.Control.MediaPropertiesChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::MediaPropertiesChangedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::IMediaPropertiesChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::IMediaPropertiesChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class PlaybackInfoChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2bdf1426-d41f-5896-897f-efc0b0fa7392"))
ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::PlaybackInfoChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::PlaybackInfoChangedEventArgs*, ABI::Windows::Media::Control::IPlaybackInfoChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Control.GlobalSystemMediaTransportControlsSession, Windows.Media.Control.PlaybackInfoChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::PlaybackInfoChangedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::IPlaybackInfoChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::IPlaybackInfoChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class TimelinePropertiesChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e8bf62af-fac1-5fff-9053-0bf191ae777e"))
ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::TimelinePropertiesChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::TimelinePropertiesChangedEventArgs*, ABI::Windows::Media::Control::ITimelinePropertiesChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Control.GlobalSystemMediaTransportControlsSession, Windows.Media.Control.TimelinePropertiesChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::TimelinePropertiesChangedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::ITimelinePropertiesChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession*,ABI::Windows::Media::Control::ITimelinePropertiesChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class CurrentSessionChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("228bd0ed-1fa2-5e9b-a6ec-42566173103b"))
ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::CurrentSessionChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::CurrentSessionChangedEventArgs*, ABI::Windows::Media::Control::ICurrentSessionChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager, Windows.Media.Control.CurrentSessionChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::CurrentSessionChangedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::ICurrentSessionChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::ICurrentSessionChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class SessionsChangedEventArgs;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2e2a8630-dc8c-530a-9746-bc984d4b029e"))
ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::SessionsChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*, ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Media::Control::SessionsChangedEventArgs*, ABI::Windows::Media::Control::ISessionsChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager, Windows.Media.Control.SessionsChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::SessionsChangedEventArgs*> __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::ISessionsChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager*,ABI::Windows::Media::Control::ISessionsChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


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



namespace ABI {
    namespace Windows {
        namespace Media {
            enum MediaPlaybackType : int;
        } /* Media */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CMedia__CMediaPlaybackType_USE
#define DEF___FIReference_1_Windows__CMedia__CMediaPlaybackType_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e289f7d8-6ba7-50ab-9f13-6e4e51d15ca4"))
IReference<enum ABI::Windows::Media::MediaPlaybackType> : IReference_impl<enum ABI::Windows::Media::MediaPlaybackType> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Media.MediaPlaybackType>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<enum ABI::Windows::Media::MediaPlaybackType> __FIReference_1_Windows__CMedia__CMediaPlaybackType_t;
#define __FIReference_1_Windows__CMedia__CMediaPlaybackType ABI::Windows::Foundation::__FIReference_1_Windows__CMedia__CMediaPlaybackType_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CMedia__CMediaPlaybackType ABI::Windows::Foundation::IReference<ABI::Windows::Media::MediaPlaybackType>
//#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_t ABI::Windows::Foundation::IReference<ABI::Windows::Media::MediaPlaybackType>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CMedia__CMediaPlaybackType_USE */



namespace ABI {
    namespace Windows {
        namespace Media {
            enum MediaPlaybackAutoRepeatMode : int;
        } /* Media */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_USE
#define DEF___FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("50a7f41f-58d5-5c4d-9475-8dd1acd65836"))
IReference<enum ABI::Windows::Media::MediaPlaybackAutoRepeatMode> : IReference_impl<enum ABI::Windows::Media::MediaPlaybackAutoRepeatMode> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Media.MediaPlaybackAutoRepeatMode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<enum ABI::Windows::Media::MediaPlaybackAutoRepeatMode> __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_t;
#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode ABI::Windows::Foundation::__FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode ABI::Windows::Foundation::IReference<ABI::Windows::Media::MediaPlaybackAutoRepeatMode>
//#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_t ABI::Windows::Foundation::IReference<ABI::Windows::Media::MediaPlaybackAutoRepeatMode>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_USE */




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




#ifndef DEF___FIReference_1_boolean_USE
#define DEF___FIReference_1_boolean_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3c00fd60-2950-5939-a21a-2d12c5a01b8a"))
IReference<bool> : IReference_impl<ABI::Windows::Foundation::Internal::AggregateType<bool, boolean>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Boolean>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<bool> __FIReference_1_boolean_t;
#define __FIReference_1_boolean ABI::Windows::Foundation::__FIReference_1_boolean_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_boolean ABI::Windows::Foundation::IReference<boolean>
//#define __FIReference_1_boolean_t ABI::Windows::Foundation::IReference<boolean>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_boolean_USE */





namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct DateTime DateTime;
            
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
        namespace Media {
            
            typedef enum MediaPlaybackAutoRepeatMode : int MediaPlaybackAutoRepeatMode;
            
        } /* Media */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Media {
            
            typedef enum MediaPlaybackType : int MediaPlaybackType;
            
        } /* Media */
    } /* Windows */} /* ABI */



#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Storage {
            namespace Streams {
                interface IRandomAccessStreamReference;
            } /* Streams */
        } /* Storage */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference ABI::Windows::Storage::Streams::IRandomAccessStreamReference

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                
                typedef enum GlobalSystemMediaTransportControlsSessionPlaybackStatus : int GlobalSystemMediaTransportControlsSessionPlaybackStatus;
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

















namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class GlobalSystemMediaTransportControlsSessionPlaybackControls;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class GlobalSystemMediaTransportControlsSessionPlaybackInfo;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                class GlobalSystemMediaTransportControlsSessionTimelineProperties;
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */














/*
 *
 * Struct Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [v1_enum, contract] */
                enum GlobalSystemMediaTransportControlsSessionPlaybackStatus : int
                {
                    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Closed = 0,
                    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Opened = 1,
                    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Changing = 2,
                    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Stopped = 3,
                    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Playing = 4,
                    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Paused = 5,
                };
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.ICurrentSessionChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.CurrentSessionChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_ICurrentSessionChangedEventArgs[] = L"Windows.Media.Control.ICurrentSessionChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("6969CB39-0BFA-5FE0-8D73-09CC5E5408E1"), exclusiveto, contract] */
                MIDL_INTERFACE("6969CB39-0BFA-5FE0-8D73-09CC5E5408E1")
                ICurrentSessionChangedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_ICurrentSessionChangedEventArgs=_uuidof(ICurrentSessionChangedEventArgs);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSession";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("7148C835-9B14-5AE2-AB85-DC9B1C14E1A8"), exclusiveto, contract] */
                MIDL_INTERFACE("7148C835-9B14-5AE2-AB85-DC9B1C14E1A8")
                IGlobalSystemMediaTransportControlsSession : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SourceAppUserModelId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryGetMediaPropertiesAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetTimelineProperties(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetPlaybackInfo(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryPlayAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryPauseAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryStopAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryRecordAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryFastForwardAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryRewindAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TrySkipNextAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TrySkipPreviousAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryChangeChannelUpAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryChangeChannelDownAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryTogglePlayPauseAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryChangeAutoRepeatModeAsync(
                        /* [in] */ABI::Windows::Media::MediaPlaybackAutoRepeatMode requestedAutoRepeatMode,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryChangePlaybackRateAsync(
                        /* [in] */DOUBLE requestedPlaybackRate,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryChangeShuffleActiveAsync(
                        /* [in] */::boolean requestedShuffleState,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryChangePlaybackPositionAsync(
                        /* [in] */INT64 requestedPlaybackPosition,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_TimelinePropertiesChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_TimelinePropertiesChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_PlaybackInfoChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_PlaybackInfoChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_MediaPropertiesChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_MediaPropertiesChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSession=_uuidof(IGlobalSystemMediaTransportControlsSession);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("CACE8EAC-E86E-504A-AB31-5FF8FF1BCE49"), exclusiveto, contract] */
                MIDL_INTERFACE("CACE8EAC-E86E-504A-AB31-5FF8FF1BCE49")
                IGlobalSystemMediaTransportControlsSessionManager : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetCurrentSession(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetSessions(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * * result
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_CurrentSessionChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_CurrentSessionChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_SessionsChanged(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_SessionsChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSessionManager=_uuidof(IGlobalSystemMediaTransportControlsSessionManager);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManagerStatics[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("2050C4EE-11A0-57DE-AED7-C97C70338245"), exclusiveto, contract] */
                MIDL_INTERFACE("2050C4EE-11A0-57DE-AED7-C97C70338245")
                IGlobalSystemMediaTransportControlsSessionManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE RequestAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSessionManagerStatics=_uuidof(IGlobalSystemMediaTransportControlsSessionManagerStatics);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("68856CF6-ADB4-54B2-AC16-05837907ACB6"), exclusiveto, contract] */
                MIDL_INTERFACE("68856CF6-ADB4-54B2-AC16-05837907ACB6")
                IGlobalSystemMediaTransportControlsSessionMediaProperties : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Title(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Subtitle(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AlbumArtist(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Artist(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AlbumTitle(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TrackNumber(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Genres(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AlbumTrackCount(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PlaybackType(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CMedia__CMediaPlaybackType * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Thumbnail(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Storage::Streams::IRandomAccessStreamReference * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSessionMediaProperties=_uuidof(IGlobalSystemMediaTransportControlsSessionMediaProperties);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("6501A3E6-BC7A-503A-BB1B-68F158F3FB03"), exclusiveto, contract] */
                MIDL_INTERFACE("6501A3E6-BC7A-503A-BB1B-68F158F3FB03")
                IGlobalSystemMediaTransportControlsSessionPlaybackControls : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPlayEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPauseEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsStopEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRecordEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsFastForwardEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRewindEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsNextEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPreviousEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsChannelUpEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsChannelDownEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPlayPauseToggleEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsShuffleEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsRepeatEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPlaybackRateEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPlaybackPositionEnabled(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSessionPlaybackControls=_uuidof(IGlobalSystemMediaTransportControlsSessionPlaybackControls);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("94B4B6CF-E8BA-51AD-87A7-C10ADE106127"), exclusiveto, contract] */
                MIDL_INTERFACE("94B4B6CF-E8BA-51AD-87A7-C10ADE106127")
                IGlobalSystemMediaTransportControlsSessionPlaybackInfo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Controls(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PlaybackStatus(
                        /* [retval, out] */__RPC__out ABI::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PlaybackType(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CMedia__CMediaPlaybackType * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AutoRepeatMode(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PlaybackRate(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_double * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsShuffleActive(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_boolean * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSessionPlaybackInfo=_uuidof(IGlobalSystemMediaTransportControlsSessionPlaybackInfo);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("EDE34136-6F25-588D-8ECF-EA5B6735AAA5"), exclusiveto, contract] */
                MIDL_INTERFACE("EDE34136-6F25-588D-8ECF-EA5B6735AAA5")
                IGlobalSystemMediaTransportControlsSessionTimelineProperties : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_StartTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EndTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MinSeekTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxSeekTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Position(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LastUpdatedTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGlobalSystemMediaTransportControlsSessionTimelineProperties=_uuidof(IGlobalSystemMediaTransportControlsSessionTimelineProperties);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IMediaPropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.MediaPropertiesChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IMediaPropertiesChangedEventArgs[] = L"Windows.Media.Control.IMediaPropertiesChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("7D3741CB-ADF0-5CEF-91BA-CFABCDD77678"), exclusiveto, contract] */
                MIDL_INTERFACE("7D3741CB-ADF0-5CEF-91BA-CFABCDD77678")
                IMediaPropertiesChangedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IMediaPropertiesChangedEventArgs=_uuidof(IMediaPropertiesChangedEventArgs);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IPlaybackInfoChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.PlaybackInfoChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IPlaybackInfoChangedEventArgs[] = L"Windows.Media.Control.IPlaybackInfoChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("786756C2-BC0D-50A5-8807-054291FEF139"), exclusiveto, contract] */
                MIDL_INTERFACE("786756C2-BC0D-50A5-8807-054291FEF139")
                IPlaybackInfoChangedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_IPlaybackInfoChangedEventArgs=_uuidof(IPlaybackInfoChangedEventArgs);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.ISessionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.SessionsChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_ISessionsChangedEventArgs[] = L"Windows.Media.Control.ISessionsChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("BBF0CD32-42C4-5A58-B317-F34BBFBD26E0"), exclusiveto, contract] */
                MIDL_INTERFACE("BBF0CD32-42C4-5A58-B317-F34BBFBD26E0")
                ISessionsChangedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_ISessionsChangedEventArgs=_uuidof(ISessionsChangedEventArgs);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.ITimelinePropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.TimelinePropertiesChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_ITimelinePropertiesChangedEventArgs[] = L"Windows.Media.Control.ITimelinePropertiesChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Media {
            namespace Control {
                /* [object, uuid("29033A2F-C923-5A77-BCAF-055FF415AD32"), exclusiveto, contract] */
                MIDL_INTERFACE("29033A2F-C923-5A77-BCAF-055FF415AD32")
                ITimelinePropertiesChangedEventArgs : public IInspectable
                {
                public:
                    
                };

                extern MIDL_CONST_ID IID & IID_ITimelinePropertiesChangedEventArgs=_uuidof(ITimelinePropertiesChangedEventArgs);
                
            } /* Control */
        } /* Media */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.CurrentSessionChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.ICurrentSessionChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_CurrentSessionChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_CurrentSessionChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_CurrentSessionChangedEventArgs[] = L"Windows.Media.Control.CurrentSessionChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSession ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSession_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSession[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionManager_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionManager[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionMediaProperties_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionMediaProperties_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionMediaProperties[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackControls_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackControls_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackControls[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackInfo_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackInfo[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionTimelineProperties_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionTimelineProperties_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionTimelineProperties[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.MediaPropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IMediaPropertiesChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_MediaPropertiesChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_MediaPropertiesChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_MediaPropertiesChangedEventArgs[] = L"Windows.Media.Control.MediaPropertiesChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.PlaybackInfoChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IPlaybackInfoChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_PlaybackInfoChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_PlaybackInfoChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_PlaybackInfoChangedEventArgs[] = L"Windows.Media.Control.PlaybackInfoChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.SessionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.ISessionsChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_SessionsChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_SessionsChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_SessionsChangedEventArgs[] = L"Windows.Media.Control.SessionsChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.TimelinePropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.ITimelinePropertiesChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_TimelinePropertiesChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_TimelinePropertiesChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_TimelinePropertiesChangedEventArgs[] = L"Windows.Media.Control.TimelinePropertiesChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs;

#endif // ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession;

typedef struct __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl;

interface __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession
{
    CONST_VTBL struct __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession;

typedef  struct __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession **first);

    END_INTERFACE
} __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl;

interface __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession
{
    CONST_VTBL struct __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession;

typedef struct __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
            /* [in] */ __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl;

interface __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession
{
    CONST_VTBL struct __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManagerVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManagerVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManagerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManagerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManagerVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManagerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties;

typedef struct __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl;

interface __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

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


enum __x_ABI_CWindows_CMedia_CMediaPlaybackType;
#if !defined(____FIReference_1_Windows__CMedia__CMediaPlaybackType_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CMedia__CMediaPlaybackType_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CMedia__CMediaPlaybackType __FIReference_1_Windows__CMedia__CMediaPlaybackType;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CMedia__CMediaPlaybackType;

typedef struct __FIReference_1_Windows__CMedia__CMediaPlaybackTypeVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackType * This, /* [retval][out] */ __RPC__out enum __x_ABI_CWindows_CMedia_CMediaPlaybackType *value);
    END_INTERFACE
} __FIReference_1_Windows__CMedia__CMediaPlaybackTypeVtbl;

interface __FIReference_1_Windows__CMedia__CMediaPlaybackType
{
    CONST_VTBL struct __FIReference_1_Windows__CMedia__CMediaPlaybackTypeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CMedia__CMediaPlaybackType_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CMedia__CMediaPlaybackType_INTERFACE_DEFINED__


enum __x_ABI_CWindows_CMedia_CMediaPlaybackAutoRepeatMode;
#if !defined(____FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode;

typedef struct __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatModeVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * This, /* [retval][out] */ __RPC__out enum __x_ABI_CWindows_CMedia_CMediaPlaybackAutoRepeatMode *value);
    END_INTERFACE
} __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatModeVtbl;

interface __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode
{
    CONST_VTBL struct __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatModeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode_INTERFACE_DEFINED__


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


#if !defined(____FIReference_1_boolean_INTERFACE_DEFINED__)
#define ____FIReference_1_boolean_INTERFACE_DEFINED__

typedef interface __FIReference_1_boolean __FIReference_1_boolean;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_boolean;

typedef struct __FIReference_1_booleanVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_boolean * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_boolean * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_boolean * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_boolean * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_boolean * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_boolean * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_boolean * This, /* [retval][out] */ __RPC__out boolean *value);
    END_INTERFACE
} __FIReference_1_booleanVtbl;

interface __FIReference_1_boolean
{
    CONST_VTBL struct __FIReference_1_booleanVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_boolean_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_boolean_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_boolean_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_boolean_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_boolean_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_boolean_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_boolean_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_boolean_INTERFACE_DEFINED__




typedef struct __x_ABI_CWindows_CFoundation_CDateTime __x_ABI_CWindows_CFoundation_CDateTime;


typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;





typedef enum __x_ABI_CWindows_CMedia_CMediaPlaybackAutoRepeatMode __x_ABI_CWindows_CMedia_CMediaPlaybackAutoRepeatMode;


typedef enum __x_ABI_CWindows_CMedia_CMediaPlaybackType __x_ABI_CWindows_CMedia_CMediaPlaybackType;



#ifndef ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
#define ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference;

#endif // ____x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CMedia_CControl_CGlobalSystemMediaTransportControlsSessionPlaybackStatus __x_ABI_CWindows_CMedia_CControl_CGlobalSystemMediaTransportControlsSessionPlaybackStatus;
































/*
 *
 * Struct Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackStatus
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CMedia_CControl_CGlobalSystemMediaTransportControlsSessionPlaybackStatus
{
    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Closed = 0,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Opened = 1,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Changing = 2,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Stopped = 3,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Playing = 4,
    GlobalSystemMediaTransportControlsSessionPlaybackStatus_Paused = 5,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.ICurrentSessionChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.CurrentSessionChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_ICurrentSessionChangedEventArgs[] = L"Windows.Media.Control.ICurrentSessionChangedEventArgs";
/* [object, uuid("6969CB39-0BFA-5FE0-8D73-09CC5E5408E1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CICurrentSessionChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSession";
/* [object, uuid("7148C835-9B14-5AE2-AB85-DC9B1C14E1A8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SourceAppUserModelId )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    HRESULT ( STDMETHODCALLTYPE *TryGetMediaPropertiesAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionMediaProperties * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetTimelineProperties )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetPlaybackInfo )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryPlayAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryPauseAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryStopAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryRecordAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryFastForwardAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryRewindAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TrySkipNextAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TrySkipPreviousAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryChangeChannelUpAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryChangeChannelDownAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryTogglePlayPauseAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryChangeAutoRepeatModeAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */__x_ABI_CWindows_CMedia_CMediaPlaybackAutoRepeatMode requestedAutoRepeatMode,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryChangePlaybackRateAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */DOUBLE requestedPlaybackRate,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryChangeShuffleActiveAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */boolean requestedShuffleState,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *TryChangePlaybackPositionAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */INT64 requestedPlaybackPosition,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_TimelinePropertiesChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CTimelinePropertiesChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_TimelinePropertiesChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_PlaybackInfoChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CPlaybackInfoChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_PlaybackInfoChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_MediaPropertiesChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession_Windows__CMedia__CControl__CMediaPropertiesChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_MediaPropertiesChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_get_SourceAppUserModelId(This,value) \
    ( (This)->lpVtbl->get_SourceAppUserModelId(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryGetMediaPropertiesAsync(This,operation) \
    ( (This)->lpVtbl->TryGetMediaPropertiesAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_GetTimelineProperties(This,result) \
    ( (This)->lpVtbl->GetTimelineProperties(This,result) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_GetPlaybackInfo(This,result) \
    ( (This)->lpVtbl->GetPlaybackInfo(This,result) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryPlayAsync(This,operation) \
    ( (This)->lpVtbl->TryPlayAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryPauseAsync(This,operation) \
    ( (This)->lpVtbl->TryPauseAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryStopAsync(This,operation) \
    ( (This)->lpVtbl->TryStopAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryRecordAsync(This,operation) \
    ( (This)->lpVtbl->TryRecordAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryFastForwardAsync(This,operation) \
    ( (This)->lpVtbl->TryFastForwardAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryRewindAsync(This,operation) \
    ( (This)->lpVtbl->TryRewindAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TrySkipNextAsync(This,operation) \
    ( (This)->lpVtbl->TrySkipNextAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TrySkipPreviousAsync(This,operation) \
    ( (This)->lpVtbl->TrySkipPreviousAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryChangeChannelUpAsync(This,operation) \
    ( (This)->lpVtbl->TryChangeChannelUpAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryChangeChannelDownAsync(This,operation) \
    ( (This)->lpVtbl->TryChangeChannelDownAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryTogglePlayPauseAsync(This,operation) \
    ( (This)->lpVtbl->TryTogglePlayPauseAsync(This,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryChangeAutoRepeatModeAsync(This,requestedAutoRepeatMode,operation) \
    ( (This)->lpVtbl->TryChangeAutoRepeatModeAsync(This,requestedAutoRepeatMode,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryChangePlaybackRateAsync(This,requestedPlaybackRate,operation) \
    ( (This)->lpVtbl->TryChangePlaybackRateAsync(This,requestedPlaybackRate,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryChangeShuffleActiveAsync(This,requestedShuffleState,operation) \
    ( (This)->lpVtbl->TryChangeShuffleActiveAsync(This,requestedShuffleState,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_TryChangePlaybackPositionAsync(This,requestedPlaybackPosition,operation) \
    ( (This)->lpVtbl->TryChangePlaybackPositionAsync(This,requestedPlaybackPosition,operation) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_add_TimelinePropertiesChanged(This,handler,token) \
    ( (This)->lpVtbl->add_TimelinePropertiesChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_remove_TimelinePropertiesChanged(This,token) \
    ( (This)->lpVtbl->remove_TimelinePropertiesChanged(This,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_add_PlaybackInfoChanged(This,handler,token) \
    ( (This)->lpVtbl->add_PlaybackInfoChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_remove_PlaybackInfoChanged(This,token) \
    ( (This)->lpVtbl->remove_PlaybackInfoChanged(This,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_add_MediaPropertiesChanged(This,handler,token) \
    ( (This)->lpVtbl->add_MediaPropertiesChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_remove_MediaPropertiesChanged(This,token) \
    ( (This)->lpVtbl->remove_MediaPropertiesChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager";
/* [object, uuid("CACE8EAC-E86E-504A-AB31-5FF8FF1BCE49"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetCurrentSession )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSession * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetSessions )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSession * * result
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_CurrentSessionChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CCurrentSessionChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_CurrentSessionChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_SessionsChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager_Windows__CMedia__CControl__CSessionsChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_SessionsChanged )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_GetCurrentSession(This,result) \
    ( (This)->lpVtbl->GetCurrentSession(This,result) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_GetSessions(This,result) \
    ( (This)->lpVtbl->GetSessions(This,result) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_add_CurrentSessionChanged(This,handler,token) \
    ( (This)->lpVtbl->add_CurrentSessionChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_remove_CurrentSessionChanged(This,token) \
    ( (This)->lpVtbl->remove_CurrentSessionChanged(This,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_add_SessionsChanged(This,handler,token) \
    ( (This)->lpVtbl->add_SessionsChanged(This,handler,token) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_remove_SessionsChanged(This,token) \
    ( (This)->lpVtbl->remove_SessionsChanged(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManager_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManagerStatics[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics";
/* [object, uuid("2050C4EE-11A0-57DE-AED7-C97C70338245"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *RequestAsync )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CMedia__CControl__CGlobalSystemMediaTransportControlsSessionManager * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStaticsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_RequestAsync(This,operation) \
    ( (This)->lpVtbl->RequestAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties";
/* [object, uuid("68856CF6-ADB4-54B2-AC16-05837907ACB6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Title )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Subtitle )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AlbumArtist )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Artist )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AlbumTitle )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TrackNumber )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Genres )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AlbumTrackCount )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PlaybackType )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CMedia__CMediaPlaybackType * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Thumbnail )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CStorage_CStreams_CIRandomAccessStreamReference * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaPropertiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_Title(This,value) \
    ( (This)->lpVtbl->get_Title(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_Subtitle(This,value) \
    ( (This)->lpVtbl->get_Subtitle(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_AlbumArtist(This,value) \
    ( (This)->lpVtbl->get_AlbumArtist(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_Artist(This,value) \
    ( (This)->lpVtbl->get_Artist(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_AlbumTitle(This,value) \
    ( (This)->lpVtbl->get_AlbumTitle(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_TrackNumber(This,value) \
    ( (This)->lpVtbl->get_TrackNumber(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_Genres(This,value) \
    ( (This)->lpVtbl->get_Genres(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_AlbumTrackCount(This,value) \
    ( (This)->lpVtbl->get_AlbumTrackCount(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_PlaybackType(This,value) \
    ( (This)->lpVtbl->get_PlaybackType(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_get_Thumbnail(This,value) \
    ( (This)->lpVtbl->get_Thumbnail(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionMediaProperties_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls";
/* [object, uuid("6501A3E6-BC7A-503A-BB1B-68F158F3FB03"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControlsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPlayEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPauseEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsStopEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRecordEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsFastForwardEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRewindEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsNextEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPreviousEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsChannelUpEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsChannelDownEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPlayPauseToggleEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsShuffleEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsRepeatEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPlaybackRateEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPlaybackPositionEnabled )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControlsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControlsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsPlayEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPlayEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsPauseEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPauseEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsStopEnabled(This,value) \
    ( (This)->lpVtbl->get_IsStopEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsRecordEnabled(This,value) \
    ( (This)->lpVtbl->get_IsRecordEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsFastForwardEnabled(This,value) \
    ( (This)->lpVtbl->get_IsFastForwardEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsRewindEnabled(This,value) \
    ( (This)->lpVtbl->get_IsRewindEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsNextEnabled(This,value) \
    ( (This)->lpVtbl->get_IsNextEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsPreviousEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPreviousEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsChannelUpEnabled(This,value) \
    ( (This)->lpVtbl->get_IsChannelUpEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsChannelDownEnabled(This,value) \
    ( (This)->lpVtbl->get_IsChannelDownEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsPlayPauseToggleEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPlayPauseToggleEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsShuffleEnabled(This,value) \
    ( (This)->lpVtbl->get_IsShuffleEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsRepeatEnabled(This,value) \
    ( (This)->lpVtbl->get_IsRepeatEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsPlaybackRateEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPlaybackRateEnabled(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_get_IsPlaybackPositionEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPlaybackPositionEnabled(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo";
/* [object, uuid("94B4B6CF-E8BA-51AD-87A7-C10ADE106127"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Controls )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackControls * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PlaybackStatus )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CMedia_CControl_CGlobalSystemMediaTransportControlsSessionPlaybackStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PlaybackType )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CMedia__CMediaPlaybackType * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AutoRepeatMode )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CMedia__CMediaPlaybackAutoRepeatMode * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PlaybackRate )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_double * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsShuffleActive )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_boolean * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfoVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_get_Controls(This,value) \
    ( (This)->lpVtbl->get_Controls(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_get_PlaybackStatus(This,value) \
    ( (This)->lpVtbl->get_PlaybackStatus(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_get_PlaybackType(This,value) \
    ( (This)->lpVtbl->get_PlaybackType(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_get_AutoRepeatMode(This,value) \
    ( (This)->lpVtbl->get_AutoRepeatMode(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_get_PlaybackRate(This,value) \
    ( (This)->lpVtbl->get_PlaybackRate(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_get_IsShuffleActive(This,value) \
    ( (This)->lpVtbl->get_IsShuffleActive(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionPlaybackInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties[] = L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties";
/* [object, uuid("EDE34136-6F25-588D-8ECF-EA5B6735AAA5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelinePropertiesVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_StartTime )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EndTime )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MinSeekTime )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxSeekTime )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Position )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LastUpdatedTime )(
        __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelinePropertiesVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelinePropertiesVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_get_StartTime(This,value) \
    ( (This)->lpVtbl->get_StartTime(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_get_EndTime(This,value) \
    ( (This)->lpVtbl->get_EndTime(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_get_MinSeekTime(This,value) \
    ( (This)->lpVtbl->get_MinSeekTime(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_get_MaxSeekTime(This,value) \
    ( (This)->lpVtbl->get_MaxSeekTime(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_get_Position(This,value) \
    ( (This)->lpVtbl->get_Position(This,value) )

#define __x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_get_LastUpdatedTime(This,value) \
    ( (This)->lpVtbl->get_LastUpdatedTime(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIGlobalSystemMediaTransportControlsSessionTimelineProperties_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IMediaPropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.MediaPropertiesChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IMediaPropertiesChangedEventArgs[] = L"Windows.Media.Control.IMediaPropertiesChangedEventArgs";
/* [object, uuid("7D3741CB-ADF0-5CEF-91BA-CFABCDD77678"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIMediaPropertiesChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.IPlaybackInfoChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.PlaybackInfoChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_IPlaybackInfoChangedEventArgs[] = L"Windows.Media.Control.IPlaybackInfoChangedEventArgs";
/* [object, uuid("786756C2-BC0D-50A5-8807-054291FEF139"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CIPlaybackInfoChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.ISessionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.SessionsChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_ISessionsChangedEventArgs[] = L"Windows.Media.Control.ISessionsChangedEventArgs";
/* [object, uuid("BBF0CD32-42C4-5A58-B317-F34BBFBD26E0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CISessionsChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Media.Control.ITimelinePropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Media.Control.TimelinePropertiesChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Media_Control_ITimelinePropertiesChangedEventArgs[] = L"Windows.Media.Control.ITimelinePropertiesChangedEventArgs";
/* [object, uuid("29033A2F-C923-5A77-BCAF-055FF415AD32"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgsVtbl;

interface __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CMedia_CControl_CITimelinePropertiesChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.CurrentSessionChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.ICurrentSessionChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_CurrentSessionChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_CurrentSessionChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_CurrentSessionChangedEventArgs[] = L"Windows.Media.Control.CurrentSessionChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSession ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSession_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSession[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionManager_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionManager[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionMediaProperties_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionMediaProperties_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionMediaProperties[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackControls_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackControls_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackControls[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackInfo_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionPlaybackInfo[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionTimelineProperties_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionTimelineProperties_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_GlobalSystemMediaTransportControlsSessionTimelineProperties[] = L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.MediaPropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IMediaPropertiesChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_MediaPropertiesChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_MediaPropertiesChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_MediaPropertiesChangedEventArgs[] = L"Windows.Media.Control.MediaPropertiesChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.PlaybackInfoChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.IPlaybackInfoChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_PlaybackInfoChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_PlaybackInfoChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_PlaybackInfoChangedEventArgs[] = L"Windows.Media.Control.PlaybackInfoChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.SessionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.ISessionsChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_SessionsChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_SessionsChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_SessionsChangedEventArgs[] = L"Windows.Media.Control.SessionsChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Media.Control.TimelinePropertiesChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Media.Control.ITimelinePropertiesChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_Media_Control_TimelinePropertiesChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Media_Control_TimelinePropertiesChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Media_Control_TimelinePropertiesChangedEventArgs[] = L"Windows.Media.Control.TimelinePropertiesChangedEventArgs";
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
#endif // __windows2Emedia2Econtrol_p_h__

#endif // __windows2Emedia2Econtrol_h__
