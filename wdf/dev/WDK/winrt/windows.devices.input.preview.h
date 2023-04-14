/* Header file automatically generated from windows.devices.input.preview.idl */
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
#ifndef __windows2Edevices2Einput2Epreview_h__
#define __windows2Edevices2Einput2Epreview_h__
#ifndef __windows2Edevices2Einput2Epreview_p_h__
#define __windows2Edevices2Einput2Epreview_p_h__


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
#include "Windows.Devices.HumanInterfaceDevice.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeDevicePreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview ABI::Windows::Devices::Input::Preview::IGazeDevicePreview

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeDeviceWatcherAddedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeDeviceWatcherPreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeDeviceWatcherRemovedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeDeviceWatcherUpdatedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeEnteredPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs ABI::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeExitedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs ABI::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeInputSourcePreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeInputSourcePreviewStatics;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazeMovedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs ABI::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    interface IGazePointPreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview ABI::Windows::Devices::Input::Preview::IGazePointPreview

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazePointPreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#define DEF___FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("ad015c81-2d80-501e-bc9a-a63f05f93bac"))
IIterator<ABI::Windows::Devices::Input::Preview::GazePointPreview*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazePointPreview*, ABI::Windows::Devices::Input::Preview::IGazePointPreview*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Devices.Input.Preview.GazePointPreview>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Devices::Input::Preview::GazePointPreview*> __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t;
#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
//#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#define DEF___FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("1cf68266-3eb7-5336-840a-3c1d9fdf5349"))
IIterable<ABI::Windows::Devices::Input::Preview::GazePointPreview*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazePointPreview*, ABI::Windows::Devices::Input::Preview::IGazePointPreview*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Devices.Input.Preview.GazePointPreview>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Devices::Input::Preview::GazePointPreview*> __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t;
#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
//#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#define DEF___FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("3d3d6148-ad02-56eb-acaf-0ea9e47c0298"))
IVectorView<ABI::Windows::Devices::Input::Preview::GazePointPreview*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazePointPreview*, ABI::Windows::Devices::Input::Preview::IGazePointPreview*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Devices.Input.Preview.GazePointPreview>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Devices::Input::Preview::GazePointPreview*> __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t;
#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
//#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#define DEF___FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("446a643d-387c-5ef6-a8ac-cca9d8a793b4"))
IVector<ABI::Windows::Devices::Input::Preview::GazePointPreview*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazePointPreview*, ABI::Windows::Devices::Input::Preview::IGazePointPreview*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<Windows.Devices.Input.Preview.GazePointPreview>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<ABI::Windows::Devices::Input::Preview::GazePointPreview*> __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t;
#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::__FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview ABI::Windows::Foundation::Collections::IVector<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
//#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_t ABI::Windows::Foundation::Collections::IVector<ABI::Windows::Devices::Input::Preview::IGazePointPreview*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeDeviceWatcherPreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("73a19afb-6081-551b-bf73-d5d23155da8e"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeDeviceWatcherPreview, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,IInspectable*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeDeviceWatcherAddedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("5bf95725-6889-544f-ba3b-dda986add8ae"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeDeviceWatcherPreview, Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeDeviceWatcherRemovedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("06c67a46-34b3-53fe-86df-ceb52e2d12e7"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeDeviceWatcherPreview, Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeDeviceWatcherUpdatedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("fe8090ac-7d5d-50a7-a3d3-f311648a7b89"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs*, ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeDeviceWatcherPreview, Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview*,ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeInputSourcePreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeEnteredPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("3876b9c5-36a0-5221-be04-4aeefb9870b2"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*, ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs*, ABI::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeInputSourcePreview, Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeExitedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("0f19b16c-73d9-5775-92a3-0f6f942e4eb0"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*, ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs*, ABI::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeInputSourcePreview, Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeMovedPreviewEventArgs;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e7c08e8f-1aba-5952-af5c-d3a2707f4fe4"))
ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*, ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs*, ABI::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.Input.Preview.GazeInputSourcePreview, Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Devices::Input::Preview::GazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs*> __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_t;
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs*>
//#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview*,ABI::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


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
        namespace Devices {
            namespace HumanInterfaceDevice {
                class HidNumericControlDescription;
            } /* HumanInterfaceDevice */
        } /* Devices */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace HumanInterfaceDevice {
                interface IHidNumericControlDescription;
            } /* HumanInterfaceDevice */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription

#endif // ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE
#define DEF___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("52b9c36e-7d95-5d1c-acab-23c19ea76f01"))
IIterator<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*, ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Devices.HumanInterfaceDevice.HidNumericControlDescription>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*> __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t;
#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>
//#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE
#define DEF___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("868f060d-e0d4-571b-b2f7-431d6984a513"))
IIterable<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*, ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Devices.HumanInterfaceDevice.HidNumericControlDescription>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*> __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t;
#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>
//#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE
#define DEF___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e02ca66c-610a-51b4-aef9-3707b697b985"))
IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*, ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Devices.HumanInterfaceDevice.HidNumericControlDescription>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription*> __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t;
#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>
//#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::IHidNumericControlDescription*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace HumanInterfaceDevice {
                class HidBooleanControlDescription;
            } /* HumanInterfaceDevice */
        } /* Devices */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace HumanInterfaceDevice {
                interface IHidBooleanControlDescription;
            } /* HumanInterfaceDevice */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription

#endif // ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE
#define DEF___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("203203b0-b7f4-542d-b0d0-9caa1fb55d7f"))
IIterator<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*, ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Devices.HumanInterfaceDevice.HidBooleanControlDescription>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*> __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t;
#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>
//#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE
#define DEF___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("d0ff0fed-a156-58bf-9411-5777df9d57bf"))
IIterable<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*, ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Devices.HumanInterfaceDevice.HidBooleanControlDescription>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*> __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t;
#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>
//#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef DEF___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE
#define DEF___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("aab72786-ec34-536f-a7c5-27394753df2c"))
IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*, ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Devices.HumanInterfaceDevice.HidBooleanControlDescription>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription*> __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t;
#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>
//#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Devices::HumanInterfaceDevice::IHidBooleanControlDescription*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

namespace ABI {
    namespace Windows {
        namespace Foundation {
            struct Point;
            
        } /* Foundation */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CFoundation__CPoint_USE
#define DEF___FIReference_1_Windows__CFoundation__CPoint_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("84f14c22-a00a-5272-8d3d-82112e66df00"))
IReference<struct ABI::Windows::Foundation::Point> : IReference_impl<struct ABI::Windows::Foundation::Point> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Foundation.Point>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::Foundation::Point> __FIReference_1_Windows__CFoundation__CPoint_t;
#define __FIReference_1_Windows__CFoundation__CPoint ABI::Windows::Foundation::__FIReference_1_Windows__CFoundation__CPoint_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CFoundation__CPoint ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::Point>
//#define __FIReference_1_Windows__CFoundation__CPoint_t ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::Point>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CFoundation__CPoint_USE */






namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace HumanInterfaceDevice {
                class HidInputReport;
            } /* HumanInterfaceDevice */
        } /* Devices */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace HumanInterfaceDevice {
                interface IHidInputReport;
            } /* HumanInterfaceDevice */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport ABI::Windows::Devices::HumanInterfaceDevice::IHidInputReport

#endif // ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport_FWD_DEFINED__






namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Point Point;
            
        } /* Foundation */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    
                    typedef enum GazeDeviceConfigurationStatePreview : int GazeDeviceConfigurationStatePreview;
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */












namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    class GazeDevicePreview;
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */





















/*
 *
 * Struct Windows.Devices.Input.Preview.GazeDeviceConfigurationStatePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [v1_enum, contract] */
                    enum GazeDeviceConfigurationStatePreview : int
                    {
                        GazeDeviceConfigurationStatePreview_Unknown = 0,
                        GazeDeviceConfigurationStatePreview_Ready = 1,
                        GazeDeviceConfigurationStatePreview_Configuring = 2,
                        GazeDeviceConfigurationStatePreview_ScreenSetupNeeded = 3,
                        GazeDeviceConfigurationStatePreview_UserCalibrationNeeded = 4,
                    };
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDevicePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDevicePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDevicePreview[] = L"Windows.Devices.Input.Preview.IGazeDevicePreview";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EE9-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EE9-B389-11E7-B201-C8D3FFB75721")
                    IGazeDevicePreview : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanTrackEyes(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CanTrackHead(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ConfigurationState(
                            /* [retval, out] */__RPC__out ABI::Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE RequestCalibrationAsync(
                            /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetNumericControlDescriptions(
                            /* [in] */UINT16 usagePage,
                            /* [in] */UINT16 usageId,
                            /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetBooleanControlDescriptions(
                            /* [in] */UINT16 usagePage,
                            /* [in] */UINT16 usageId,
                            /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeDevicePreview=_uuidof(IGazeDevicePreview);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherAddedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherAddedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherAddedPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EED-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EED-B389-11E7-B201-C8D3FFB75721")
                    IGazeDeviceWatcherAddedPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Device(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazeDevicePreview * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeDeviceWatcherAddedPreviewEventArgs=_uuidof(IGazeDeviceWatcherAddedPreviewEventArgs);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherPreview";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EE7-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EE7-B389-11E7-B201-C8D3FFB75721")
                    IGazeDeviceWatcherPreview : public IInspectable
                    {
                    public:
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Added(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Added(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Removed(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Removed(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Updated(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Updated(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_EnumerationCompleted(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_EnumerationCompleted(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Start(void) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Stop(void) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeDeviceWatcherPreview=_uuidof(IGazeDeviceWatcherPreview);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherRemovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherRemovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherRemovedPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("F2631F08-0E3F-431F-A606-50B35AF94A1C"), exclusiveto, contract] */
                    MIDL_INTERFACE("F2631F08-0E3F-431F-A606-50B35AF94A1C")
                    IGazeDeviceWatcherRemovedPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Device(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazeDevicePreview * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeDeviceWatcherRemovedPreviewEventArgs=_uuidof(IGazeDeviceWatcherRemovedPreviewEventArgs);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherUpdatedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherUpdatedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherUpdatedPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("7FE830EF-7F08-4737-88E1-4A83AE4E4885"), exclusiveto, contract] */
                    MIDL_INTERFACE("7FE830EF-7F08-4737-88E1-4A83AE4E4885")
                    IGazeDeviceWatcherUpdatedPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Device(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazeDevicePreview * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeDeviceWatcherUpdatedPreviewEventArgs=_uuidof(IGazeDeviceWatcherUpdatedPreviewEventArgs);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeEnteredPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeEnteredPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("2567BF43-1225-489F-9DD1-DAA7C50FBF4B"), exclusiveto, contract] */
                    MIDL_INTERFACE("2567BF43-1225-489F-9DD1-DAA7C50FBF4B")
                    IGazeEnteredPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CurrentPoint(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazePointPreview * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeEnteredPreviewEventArgs=_uuidof(IGazeEnteredPreviewEventArgs);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeExitedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeExitedPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("5D0AF07E-7D83-40EF-9F0A-FBC1BBDCC5AC"), exclusiveto, contract] */
                    MIDL_INTERFACE("5D0AF07E-7D83-40EF-9F0A-FBC1BBDCC5AC")
                    IGazeExitedPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CurrentPoint(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazePointPreview * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeExitedPreviewEventArgs=_uuidof(IGazeExitedPreviewEventArgs);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeInputSourcePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeInputSourcePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeInputSourcePreview[] = L"Windows.Devices.Input.Preview.IGazeInputSourcePreview";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EE8-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EE8-B389-11E7-B201-C8D3FFB75721")
                    IGazeInputSourcePreview : public IInspectable
                    {
                    public:
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_GazeMoved(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_GazeMoved(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_GazeEntered(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_GazeEntered(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_GazeExited(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_GazeExited(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeInputSourcePreview=_uuidof(IGazeInputSourcePreview);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeInputSourcePreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeInputSourcePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeInputSourcePreviewStatics[] = L"Windows.Devices.Input.Preview.IGazeInputSourcePreviewStatics";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EE6-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EE6-B389-11E7-B201-C8D3FFB75721")
                    IGazeInputSourcePreviewStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazeInputSourcePreview * * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE CreateWatcher(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeInputSourcePreviewStatics=_uuidof(IGazeInputSourcePreviewStatics);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeMovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeMovedPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EEB-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EEB-B389-11E7-B201-C8D3FFB75721")
                    IGazeMovedPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CurrentPoint(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazePointPreview * * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetIntermediatePoints(
                            /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazeMovedPreviewEventArgs=_uuidof(IGazeMovedPreviewEventArgs);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazePointPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazePointPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazePointPreview[] = L"Windows.Devices.Input.Preview.IGazePointPreview";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Input {
                namespace Preview {
                    /* [object, uuid("E79E7EEA-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
                    MIDL_INTERFACE("E79E7EEA-B389-11E7-B201-C8D3FFB75721")
                    IGazePointPreview : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SourceDevice(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::Input::Preview::IGazeDevicePreview * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EyeGazePosition(
                            /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CPoint * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HeadGazePosition(
                            /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CPoint * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Timestamp(
                            /* [retval, out] */__RPC__out UINT64 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HidInputReport(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Devices::HumanInterfaceDevice::IHidInputReport * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IGazePointPreview=_uuidof(IGazePointPreview);
                    
                } /* Preview */
            } /* Input */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDevicePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDevicePreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDevicePreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDevicePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDevicePreview[] = L"Windows.Devices.Input.Preview.GazeDevicePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherAddedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherAddedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherAddedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherAddedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherPreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherPreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherPreview[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherRemovedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherRemovedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherRemovedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherRemovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherUpdatedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherUpdatedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherUpdatedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherUpdatedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeEnteredPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeEnteredPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeEnteredPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeEnteredPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeExitedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeExitedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeExitedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeExitedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeInputSourcePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Input.Preview.IGazeInputSourcePreviewStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeInputSourcePreview ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeInputSourcePreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeInputSourcePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeInputSourcePreview[] = L"Windows.Devices.Input.Preview.GazeInputSourcePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeMovedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeMovedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeMovedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeMovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazePointPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazePointPreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazePointPreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazePointPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazePointPreview[] = L"Windows.Devices.Input.Preview.GazePointPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview;

#endif // ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

typedef struct __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl;

interface __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview
{
    CONST_VTBL struct __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

typedef  struct __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CDevices__CInput__CPreview__CGazePointPreview **first);

    END_INTERFACE
} __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl;

interface __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview
{
    CONST_VTBL struct __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

typedef struct __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
            /* [in] */ __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl;

interface __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview
{
    CONST_VTBL struct __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__)
#define ____FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

typedef interface __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview;

typedef struct __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [out] */ __RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_Windows__CDevices__CInput__CPreview__CGazePointPreview **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This, /* [in] */ __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * *value);

    END_INTERFACE
} __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl;

interface __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview
{
    CONST_VTBL struct __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreviewVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

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


#ifndef ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription;

#endif // ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription;

typedef struct __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl;

interface __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription
{
    CONST_VTBL struct __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription;

typedef  struct __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription **first);

    END_INTERFACE
} __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl;

interface __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription
{
    CONST_VTBL struct __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription;

typedef struct __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
            /* [in] */ __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl;

interface __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription
{
    CONST_VTBL struct __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescriptionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

#ifndef ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription;

#endif // ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription;

typedef struct __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl;

interface __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription
{
    CONST_VTBL struct __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription;

typedef  struct __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription **first);

    END_INTERFACE
} __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl;

interface __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription
{
    CONST_VTBL struct __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000
#if !defined(____FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription;

typedef struct __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
            /* [in] */ __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidBooleanControlDescription * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl;

interface __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription
{
    CONST_VTBL struct __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescriptionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x10000

struct __x_ABI_CWindows_CFoundation_CPoint;

#if !defined(____FIReference_1_Windows__CFoundation__CPoint_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CFoundation__CPoint_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CFoundation__CPoint __FIReference_1_Windows__CFoundation__CPoint;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CFoundation__CPoint;

typedef struct __FIReference_1_Windows__CFoundation__CPointVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CFoundation__CPoint * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CFoundation__CPoint * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CFoundation__CPoint * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CFoundation__CPoint * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CFoundation__CPoint * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CFoundation__CPoint * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CFoundation__CPoint * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CFoundation_CPoint *value);
    END_INTERFACE
} __FIReference_1_Windows__CFoundation__CPointVtbl;

interface __FIReference_1_Windows__CFoundation__CPoint
{
    CONST_VTBL struct __FIReference_1_Windows__CFoundation__CPointVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CFoundation__CPoint_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CFoundation__CPoint_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CFoundation__CPoint_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CFoundation__CPoint_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CFoundation__CPoint_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CFoundation__CPoint_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CFoundation__CPoint_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CFoundation__CPoint_INTERFACE_DEFINED__




#ifndef ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport;

#endif // ____x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport_FWD_DEFINED__







typedef struct __x_ABI_CWindows_CFoundation_CPoint __x_ABI_CWindows_CFoundation_CPoint;





typedef enum __x_ABI_CWindows_CDevices_CInput_CPreview_CGazeDeviceConfigurationStatePreview __x_ABI_CWindows_CDevices_CInput_CPreview_CGazeDeviceConfigurationStatePreview;
































/*
 *
 * Struct Windows.Devices.Input.Preview.GazeDeviceConfigurationStatePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CInput_CPreview_CGazeDeviceConfigurationStatePreview
{
    GazeDeviceConfigurationStatePreview_Unknown = 0,
    GazeDeviceConfigurationStatePreview_Ready = 1,
    GazeDeviceConfigurationStatePreview_Configuring = 2,
    GazeDeviceConfigurationStatePreview_ScreenSetupNeeded = 3,
    GazeDeviceConfigurationStatePreview_UserCalibrationNeeded = 4,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDevicePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDevicePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDevicePreview[] = L"Windows.Devices.Input.Preview.IGazeDevicePreview";
/* [object, uuid("E79E7EE9-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanTrackEyes )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CanTrackHead )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ConfigurationState )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CInput_CPreview_CGazeDeviceConfigurationStatePreview * value
        );
    HRESULT ( STDMETHODCALLTYPE *RequestCalibrationAsync )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetNumericControlDescriptions )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [in] */UINT16 usagePage,
        /* [in] */UINT16 usageId,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription * * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetBooleanControlDescriptions )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * This,
        /* [in] */UINT16 usagePage,
        /* [in] */UINT16 usageId,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidBooleanControlDescription * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreviewVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_get_CanTrackEyes(This,value) \
    ( (This)->lpVtbl->get_CanTrackEyes(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_get_CanTrackHead(This,value) \
    ( (This)->lpVtbl->get_CanTrackHead(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_get_ConfigurationState(This,value) \
    ( (This)->lpVtbl->get_ConfigurationState(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_RequestCalibrationAsync(This,operation) \
    ( (This)->lpVtbl->RequestCalibrationAsync(This,operation) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_GetNumericControlDescriptions(This,usagePage,usageId,result) \
    ( (This)->lpVtbl->GetNumericControlDescriptions(This,usagePage,usageId,result) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_GetBooleanControlDescriptions(This,usagePage,usageId,result) \
    ( (This)->lpVtbl->GetBooleanControlDescriptions(This,usagePage,usageId,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherAddedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherAddedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherAddedPreviewEventArgs";
/* [object, uuid("E79E7EED-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Device )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_get_Device(This,value) \
    ( (This)->lpVtbl->get_Device(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherAddedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherPreview";
/* [object, uuid("E79E7EE7-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Added )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherAddedPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Added )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Removed )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherRemovedPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Removed )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Updated )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherUpdatedPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Updated )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_EnumerationCompleted )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeDeviceWatcherPreview_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_EnumerationCompleted )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *Start )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This
        );
    HRESULT ( STDMETHODCALLTYPE *Stop )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreviewVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_add_Added(This,handler,token) \
    ( (This)->lpVtbl->add_Added(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_remove_Added(This,token) \
    ( (This)->lpVtbl->remove_Added(This,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_add_Removed(This,handler,token) \
    ( (This)->lpVtbl->add_Removed(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_remove_Removed(This,token) \
    ( (This)->lpVtbl->remove_Removed(This,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_add_Updated(This,handler,token) \
    ( (This)->lpVtbl->add_Updated(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_remove_Updated(This,token) \
    ( (This)->lpVtbl->remove_Updated(This,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_add_EnumerationCompleted(This,handler,token) \
    ( (This)->lpVtbl->add_EnumerationCompleted(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_remove_EnumerationCompleted(This,token) \
    ( (This)->lpVtbl->remove_EnumerationCompleted(This,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_Start(This) \
    ( (This)->lpVtbl->Start(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_Stop(This) \
    ( (This)->lpVtbl->Stop(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherRemovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherRemovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherRemovedPreviewEventArgs";
/* [object, uuid("F2631F08-0E3F-431F-A606-50B35AF94A1C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Device )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_get_Device(This,value) \
    ( (This)->lpVtbl->get_Device(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherRemovedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeDeviceWatcherUpdatedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeDeviceWatcherUpdatedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeDeviceWatcherUpdatedPreviewEventArgs";
/* [object, uuid("7FE830EF-7F08-4737-88E1-4A83AE4E4885"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Device )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_get_Device(This,value) \
    ( (This)->lpVtbl->get_Device(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherUpdatedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeEnteredPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeEnteredPreviewEventArgs";
/* [object, uuid("2567BF43-1225-489F-9DD1-DAA7C50FBF4B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CurrentPoint )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_get_CurrentPoint(This,value) \
    ( (This)->lpVtbl->get_CurrentPoint(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeEnteredPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeExitedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeExitedPreviewEventArgs";
/* [object, uuid("5D0AF07E-7D83-40EF-9F0A-FBC1BBDCC5AC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CurrentPoint )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_get_CurrentPoint(This,value) \
    ( (This)->lpVtbl->get_CurrentPoint(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeExitedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeInputSourcePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeInputSourcePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeInputSourcePreview[] = L"Windows.Devices.Input.Preview.IGazeInputSourcePreview";
/* [object, uuid("E79E7EE8-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_GazeMoved )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeMovedPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_GazeMoved )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_GazeEntered )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeEnteredPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_GazeEntered )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_GazeExited )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CDevices__CInput__CPreview__CGazeInputSourcePreview_Windows__CDevices__CInput__CPreview__CGazeExitedPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_GazeExited )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_add_GazeMoved(This,handler,token) \
    ( (This)->lpVtbl->add_GazeMoved(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_remove_GazeMoved(This,token) \
    ( (This)->lpVtbl->remove_GazeMoved(This,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_add_GazeEntered(This,handler,token) \
    ( (This)->lpVtbl->add_GazeEntered(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_remove_GazeEntered(This,token) \
    ( (This)->lpVtbl->remove_GazeEntered(This,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_add_GazeExited(This,handler,token) \
    ( (This)->lpVtbl->add_GazeExited(This,handler,token) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_remove_GazeExited(This,token) \
    ( (This)->lpVtbl->remove_GazeExited(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeInputSourcePreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeInputSourcePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeInputSourcePreviewStatics[] = L"Windows.Devices.Input.Preview.IGazeInputSourcePreviewStatics";
/* [object, uuid("E79E7EE6-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreview * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateWatcher )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDeviceWatcherPreview * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStaticsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_GetForCurrentView(This,result) \
    ( (This)->lpVtbl->GetForCurrentView(This,result) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_CreateWatcher(This,result) \
    ( (This)->lpVtbl->CreateWatcher(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeInputSourcePreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazeMovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.IGazeMovedPreviewEventArgs";
/* [object, uuid("E79E7EEB-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CurrentPoint )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetIntermediatePoints )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CDevices__CInput__CPreview__CGazePointPreview * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_get_CurrentPoint(This,value) \
    ( (This)->lpVtbl->get_CurrentPoint(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_GetIntermediatePoints(This,result) \
    ( (This)->lpVtbl->GetIntermediatePoints(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeMovedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Input.Preview.IGazePointPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Input.Preview.GazePointPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Input_Preview_IGazePointPreview[] = L"Windows.Devices.Input.Preview.IGazePointPreview";
/* [object, uuid("E79E7EEA-B389-11E7-B201-C8D3FFB75721"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SourceDevice )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazeDevicePreview * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EyeGazePosition )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CPoint * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HeadGazePosition )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CPoint * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Timestamp )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
        /* [retval, out] */__RPC__out UINT64 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HidInputReport )(
        __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreviewVtbl;

interface __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_get_SourceDevice(This,value) \
    ( (This)->lpVtbl->get_SourceDevice(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_get_EyeGazePosition(This,value) \
    ( (This)->lpVtbl->get_EyeGazePosition(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_get_HeadGazePosition(This,value) \
    ( (This)->lpVtbl->get_HeadGazePosition(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_get_Timestamp(This,value) \
    ( (This)->lpVtbl->get_Timestamp(This,value) )

#define __x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_get_HidInputReport(This,value) \
    ( (This)->lpVtbl->get_HidInputReport(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview;
#endif /* !defined(____x_ABI_CWindows_CDevices_CInput_CPreview_CIGazePointPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDevicePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDevicePreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDevicePreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDevicePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDevicePreview[] = L"Windows.Devices.Input.Preview.GazeDevicePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherAddedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherAddedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherAddedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherAddedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherAddedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherPreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherPreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherPreview[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherRemovedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherRemovedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherRemovedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherRemovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherRemovedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeDeviceWatcherUpdatedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherUpdatedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeDeviceWatcherUpdatedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeDeviceWatcherUpdatedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeDeviceWatcherUpdatedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeEnteredPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeEnteredPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeEnteredPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeEnteredPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeEnteredPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeExitedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeExitedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeExitedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeExitedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeExitedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeInputSourcePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Input.Preview.IGazeInputSourcePreviewStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeInputSourcePreview ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeInputSourcePreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeInputSourcePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeInputSourcePreview[] = L"Windows.Devices.Input.Preview.GazeInputSourcePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazeMovedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazeMovedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazeMovedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazeMovedPreviewEventArgs[] = L"Windows.Devices.Input.Preview.GazeMovedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Input.Preview.GazePointPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Input.Preview.IGazePointPreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Input_Preview_GazePointPreview_DEFINED
#define RUNTIMECLASS_Windows_Devices_Input_Preview_GazePointPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Input_Preview_GazePointPreview[] = L"Windows.Devices.Input.Preview.GazePointPreview";
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
#endif // __windows2Edevices2Einput2Epreview_p_h__

#endif // __windows2Edevices2Einput2Epreview_h__
