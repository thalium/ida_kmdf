/* Header file automatically generated from windows.graphics.capture.idl */
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
#ifndef __windows2Egraphics2Ecapture_h__
#define __windows2Egraphics2Ecapture_h__
#ifndef __windows2Egraphics2Ecapture_p_h__
#define __windows2Egraphics2Ecapture_p_h__


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
#include "Windows.Graphics.h"
#include "Windows.Graphics.DirectX.h"
#include "Windows.Graphics.DirectX.Direct3D11.h"
#include "Windows.System.h"
#include "Windows.UI.Composition.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IDirect3D11CaptureFrame;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame ABI::Windows::Graphics::Capture::IDirect3D11CaptureFrame

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IDirect3D11CaptureFramePool;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePool

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IDirect3D11CaptureFramePoolStatics;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IDirect3D11CaptureFramePoolStatics2;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IGraphicsCaptureItem;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem ABI::Windows::Graphics::Capture::IGraphicsCaptureItem

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IGraphicsCaptureItemStatics;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics ABI::Windows::Graphics::Capture::IGraphicsCaptureItemStatics

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IGraphicsCapturePicker;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker ABI::Windows::Graphics::Capture::IGraphicsCapturePicker

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IGraphicsCaptureSession;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession ABI::Windows::Graphics::Capture::IGraphicsCaptureSession

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                interface IGraphicsCaptureSessionStatics;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics ABI::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                class GraphicsCaptureItem;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("43004a3c-ffe7-5352-85a6-7bc41b782fca"))
IAsyncOperationCompletedHandler<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*, ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Graphics.Capture.GraphicsCaptureItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*> __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_USE
#define DEF___FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("01ccf2ae-1059-5d57-a805-0a1dfc54cab9"))
IAsyncOperation<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*, ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Graphics.Capture.GraphicsCaptureItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*> __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_t;
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>
//#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                class Direct3D11CaptureFramePool;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("51a947f7-79cf-5a3e-a3a5-1289cfa6dfe8"))
ITypedEventHandler<ABI::Windows::Graphics::Capture::Direct3D11CaptureFramePool*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Capture::Direct3D11CaptureFramePool*, ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePool*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Graphics.Capture.Direct3D11CaptureFramePool, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Graphics::Capture::Direct3D11CaptureFramePool*,IInspectable*> __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePool*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePool*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("e9c610c0-a68c-5bd9-8021-8589346eeee2"))
ITypedEventHandler<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*, ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Graphics.Capture.GraphicsCaptureItem, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Graphics::Capture::GraphicsCaptureItem*,IInspectable*> __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Graphics::Capture::IGraphicsCaptureItem*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



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




#ifndef ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace DirectX {
                namespace Direct3D11 {
                    interface IDirect3DDevice;
                } /* Direct3D11 */
            } /* DirectX */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice

#endif // ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace DirectX {
                namespace Direct3D11 {
                    interface IDirect3DSurface;
                } /* Direct3D11 */
            } /* DirectX */
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface

#endif // ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface_FWD_DEFINED__






namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace DirectX {
                
                typedef enum DirectXPixelFormat : int DirectXPixelFormat;
                
            } /* DirectX */
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
            namespace Composition {
                class Visual;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface IVisual;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CIVisual ABI::Windows::UI::Composition::IVisual

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__














namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                class Direct3D11CaptureFrame;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                class GraphicsCapturePicker;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                class GraphicsCaptureSession;
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */










/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFrame
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFrame[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFrame";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("FA50C623-38DA-4B32-ACF3-FA9734AD800E"), exclusiveto, contract] */
                MIDL_INTERFACE("FA50C623-38DA-4B32-ACF3-FA9734AD800E")
                IDirect3D11CaptureFrame : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Surface(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SystemRelativeTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ContentSize(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::SizeInt32 * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDirect3D11CaptureFrame=_uuidof(IDirect3D11CaptureFrame);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFramePool
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFramePool[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePool";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("24EB6D22-1975-422E-82E7-780DBD8DDF24"), exclusiveto, contract] */
                MIDL_INTERFACE("24EB6D22-1975-422E-82E7-780DBD8DDF24")
                IDirect3D11CaptureFramePool : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Recreate(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice * device,
                        /* [in] */ABI::Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat,
                        /* [in] */INT32 numberOfBuffers,
                        /* [in] */ABI::Windows::Graphics::SizeInt32 size
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TryGetNextFrame(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Capture::IDirect3D11CaptureFrame * * result
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_FrameArrived(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_FrameArrived(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateCaptureSession(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::Capture::IGraphicsCaptureItem * item,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Capture::IGraphicsCaptureSession * * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DispatcherQueue(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::System::IDispatcherQueue * * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDirect3D11CaptureFramePool=_uuidof(IDirect3D11CaptureFramePool);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("7784056A-67AA-4D53-AE54-1088D5A8CA21"), exclusiveto, contract] */
                MIDL_INTERFACE("7784056A-67AA-4D53-AE54-1088D5A8CA21")
                IDirect3D11CaptureFramePoolStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE Create(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice * device,
                        /* [in] */ABI::Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat,
                        /* [in] */INT32 numberOfBuffers,
                        /* [in] */ABI::Windows::Graphics::SizeInt32 size,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePool * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDirect3D11CaptureFramePoolStatics=_uuidof(IDirect3D11CaptureFramePoolStatics);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("589B103F-6BBC-5DF5-A991-02E28B3B66D5"), exclusiveto, contract] */
                MIDL_INTERFACE("589B103F-6BBC-5DF5-A991-02E28B3B66D5")
                IDirect3D11CaptureFramePoolStatics2 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFreeThreaded(
                        /* [in] */__RPC__in_opt ABI::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice * device,
                        /* [in] */ABI::Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat,
                        /* [in] */INT32 numberOfBuffers,
                        /* [in] */ABI::Windows::Graphics::SizeInt32 size,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Capture::IDirect3D11CaptureFramePool * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDirect3D11CaptureFramePoolStatics2=_uuidof(IDirect3D11CaptureFramePoolStatics2);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureItem
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureItem[] = L"Windows.Graphics.Capture.IGraphicsCaptureItem";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("79C3F95B-31F7-4EC2-A464-632EF5D30760"), exclusiveto, contract] */
                MIDL_INTERFACE("79C3F95B-31F7-4EC2-A464-632EF5D30760")
                IGraphicsCaptureItem : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Size(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::SizeInt32 * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_Closed(
                        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_Closed(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGraphicsCaptureItem=_uuidof(IGraphicsCaptureItem);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureItemStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureItem
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureItemStatics[] = L"Windows.Graphics.Capture.IGraphicsCaptureItemStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("A87EBEA5-457C-5788-AB47-0CF1D3637E74"), exclusiveto, contract] */
                MIDL_INTERFACE("A87EBEA5-457C-5788-AB47-0CF1D3637E74")
                IGraphicsCaptureItemStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateFromVisual(
                        /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * visual,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Graphics::Capture::IGraphicsCaptureItem * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGraphicsCaptureItemStatics=_uuidof(IGraphicsCaptureItemStatics);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCapturePicker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCapturePicker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCapturePicker[] = L"Windows.Graphics.Capture.IGraphicsCapturePicker";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("5A1711B3-AD79-4B4A-9336-1318FDDE3539"), exclusiveto, contract] */
                MIDL_INTERFACE("5A1711B3-AD79-4B4A-9336-1318FDDE3539")
                IGraphicsCapturePicker : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE PickSingleItemAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGraphicsCapturePicker=_uuidof(IGraphicsCapturePicker);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureSession[] = L"Windows.Graphics.Capture.IGraphicsCaptureSession";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("814E42A9-F70F-4AD7-939B-FDDCC6EB880D"), exclusiveto, contract] */
                MIDL_INTERFACE("814E42A9-F70F-4AD7-939B-FDDCC6EB880D")
                IGraphicsCaptureSession : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE StartCapture(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGraphicsCaptureSession=_uuidof(IGraphicsCaptureSession);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureSessionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics[] = L"Windows.Graphics.Capture.IGraphicsCaptureSessionStatics";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            namespace Capture {
                /* [object, uuid("2224A540-5974-49AA-B232-0882536F4CB5"), exclusiveto, contract] */
                MIDL_INTERFACE("2224A540-5974-49AA-B232-0882536F4CB5")
                IGraphicsCaptureSessionStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE IsSupported(
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IGraphicsCaptureSessionStatics=_uuidof(IGraphicsCaptureSessionStatics);
                
            } /* Capture */
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.Direct3D11CaptureFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IDirect3D11CaptureFrame ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFrame_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFrame_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_Direct3D11CaptureFrame[] = L"Windows.Graphics.Capture.Direct3D11CaptureFrame";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2 interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IDirect3D11CaptureFramePool ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFramePool_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFramePool_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_Direct3D11CaptureFramePool[] = L"Windows.Graphics.Capture.Direct3D11CaptureFramePool";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.GraphicsCaptureItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Capture.IGraphicsCaptureItemStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IGraphicsCaptureItem ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureItem_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_GraphicsCaptureItem[] = L"Windows.Graphics.Capture.GraphicsCaptureItem";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.GraphicsCapturePicker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IGraphicsCapturePicker ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCapturePicker_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCapturePicker_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_GraphicsCapturePicker[] = L"Windows.Graphics.Capture.GraphicsCapturePicker";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.GraphicsCaptureSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Capture.IGraphicsCaptureSessionStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IGraphicsCaptureSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureSession_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_GraphicsCaptureSession[] = L"Windows.Graphics.Capture.GraphicsCaptureSession";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics;

#endif // ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItemVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem;

typedef struct __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItemVtbl;

interface __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;




#ifndef ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice;

#endif // ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface;

#endif // ____x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface_FWD_DEFINED__







typedef enum __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat;





typedef struct __x_ABI_CWindows_CGraphics_CSizeInt32 __x_ABI_CWindows_CGraphics_CSizeInt32;



#ifndef ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CIDispatcherQueue __x_ABI_CWindows_CSystem_CIDispatcherQueue;

#endif // ____x_ABI_CWindows_CSystem_CIDispatcherQueue_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVisual __x_ABI_CWindows_CUI_CComposition_CIVisual;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__



























/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFrame
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFrame[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFrame";
/* [object, uuid("FA50C623-38DA-4B32-ACF3-FA9734AD800E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrameVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Surface )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DSurface * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SystemRelativeTime )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ContentSize )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CSizeInt32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrameVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrameVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_get_Surface(This,value) \
    ( (This)->lpVtbl->get_Surface(This,value) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_get_SystemRelativeTime(This,value) \
    ( (This)->lpVtbl->get_SystemRelativeTime(This,value) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_get_ContentSize(This,value) \
    ( (This)->lpVtbl->get_ContentSize(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFramePool
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFramePool[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePool";
/* [object, uuid("24EB6D22-1975-422E-82E7-780DBD8DDF24"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Recreate )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice * device,
        /* [in] */__x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat pixelFormat,
        /* [in] */INT32 numberOfBuffers,
        /* [in] */__x_ABI_CWindows_CGraphics_CSizeInt32 size
        );
    HRESULT ( STDMETHODCALLTYPE *TryGetNextFrame )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFrame * * result
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_FrameArrived )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CCapture__CDirect3D11CaptureFramePool_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_FrameArrived )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *CreateCaptureSession )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * item,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DispatcherQueue )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSystem_CIDispatcherQueue * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_Recreate(This,device,pixelFormat,numberOfBuffers,size) \
    ( (This)->lpVtbl->Recreate(This,device,pixelFormat,numberOfBuffers,size) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_TryGetNextFrame(This,result) \
    ( (This)->lpVtbl->TryGetNextFrame(This,result) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_add_FrameArrived(This,handler,token) \
    ( (This)->lpVtbl->add_FrameArrived(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_remove_FrameArrived(This,token) \
    ( (This)->lpVtbl->remove_FrameArrived(This,token) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_CreateCaptureSession(This,item,result) \
    ( (This)->lpVtbl->CreateCaptureSession(This,item,result) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_get_DispatcherQueue(This,value) \
    ( (This)->lpVtbl->get_DispatcherQueue(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics";
/* [object, uuid("7784056A-67AA-4D53-AE54-1088D5A8CA21"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice * device,
        /* [in] */__x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat pixelFormat,
        /* [in] */INT32 numberOfBuffers,
        /* [in] */__x_ABI_CWindows_CGraphics_CSizeInt32 size,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_Create(This,device,pixelFormat,numberOfBuffers,size,result) \
    ( (This)->lpVtbl->Create(This,device,pixelFormat,numberOfBuffers,size,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2[] = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2";
/* [object, uuid("589B103F-6BBC-5DF5-A991-02E28B3B66D5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFreeThreaded )(
        __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CGraphics_CDirectX_CDirect3D11_CIDirect3DDevice * device,
        /* [in] */__x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat pixelFormat,
        /* [in] */INT32 numberOfBuffers,
        /* [in] */__x_ABI_CWindows_CGraphics_CSizeInt32 size,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePool * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2Vtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_CreateFreeThreaded(This,device,pixelFormat,numberOfBuffers,size,result) \
    ( (This)->lpVtbl->CreateFreeThreaded(This,device,pixelFormat,numberOfBuffers,size,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIDirect3D11CaptureFramePoolStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureItem
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureItem[] = L"Windows.Graphics.Capture.IGraphicsCaptureItem";
/* [object, uuid("79C3F95B-31F7-4EC2-A464-632EF5D30760"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Size )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CSizeInt32 * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_Closed )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CGraphics__CCapture__CGraphicsCaptureItem_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_Closed )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_get_Size(This,value) \
    ( (This)->lpVtbl->get_Size(This,value) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_add_Closed(This,handler,token) \
    ( (This)->lpVtbl->add_Closed(This,handler,token) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_remove_Closed(This,token) \
    ( (This)->lpVtbl->remove_Closed(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureItemStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureItem
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureItemStatics[] = L"Windows.Graphics.Capture.IGraphicsCaptureItemStatics";
/* [object, uuid("A87EBEA5-457C-5788-AB47-0CF1D3637E74"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromVisual )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * visual,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItem * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_CreateFromVisual(This,visual,result) \
    ( (This)->lpVtbl->CreateFromVisual(This,visual,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureItemStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCapturePicker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCapturePicker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCapturePicker[] = L"Windows.Graphics.Capture.IGraphicsCapturePicker";
/* [object, uuid("5A1711B3-AD79-4B4A-9336-1318FDDE3539"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePickerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *PickSingleItemAsync )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CGraphics__CCapture__CGraphicsCaptureItem * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePickerVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePickerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_PickSingleItemAsync(This,operation) \
    ( (This)->lpVtbl->PickSingleItemAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCapturePicker_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureSession[] = L"Windows.Graphics.Capture.IGraphicsCaptureSession";
/* [object, uuid("814E42A9-F70F-4AD7-939B-FDDCC6EB880D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *StartCapture )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_StartCapture(This) \
    ( (This)->lpVtbl->StartCapture(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSession_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Graphics.Capture.IGraphicsCaptureSessionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Graphics.Capture.GraphicsCaptureSession
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics[] = L"Windows.Graphics.Capture.IGraphicsCaptureSessionStatics";
/* [object, uuid("2224A540-5974-49AA-B232-0882536F4CB5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *IsSupported )(
        __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStaticsVtbl;

interface __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_IsSupported(This,result) \
    ( (This)->lpVtbl->IsSupported(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CCapture_CIGraphicsCaptureSessionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.Direct3D11CaptureFrame
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IDirect3D11CaptureFrame ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFrame_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFrame_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_Direct3D11CaptureFrame[] = L"Windows.Graphics.Capture.Direct3D11CaptureFrame";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.Direct3D11CaptureFramePool
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2 interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IDirect3D11CaptureFramePool ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFramePool_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_Direct3D11CaptureFramePool_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_Direct3D11CaptureFramePool[] = L"Windows.Graphics.Capture.Direct3D11CaptureFramePool";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.GraphicsCaptureItem
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Capture.IGraphicsCaptureItemStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IGraphicsCaptureItem ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureItem_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_GraphicsCaptureItem[] = L"Windows.Graphics.Capture.GraphicsCaptureItem";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.GraphicsCapturePicker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IGraphicsCapturePicker ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCapturePicker_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCapturePicker_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_GraphicsCapturePicker[] = L"Windows.Graphics.Capture.GraphicsCapturePicker";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Graphics.Capture.GraphicsCaptureSession
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Graphics.Capture.IGraphicsCaptureSessionStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Graphics.Capture.IGraphicsCaptureSession ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureSession_DEFINED
#define RUNTIMECLASS_Windows_Graphics_Capture_GraphicsCaptureSession_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Graphics_Capture_GraphicsCaptureSession[] = L"Windows.Graphics.Capture.GraphicsCaptureSession";
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
#endif // __windows2Egraphics2Ecapture_p_h__

#endif // __windows2Egraphics2Ecapture_h__
