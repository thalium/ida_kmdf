/* Header file automatically generated from windows.web.ui.interop.idl */
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
#ifndef __windows2Eweb2Eui2Einterop_h__
#define __windows2Eweb2Eui2Einterop_h__
#ifndef __windows2Eweb2Eui2Einterop_p_h__
#define __windows2Eweb2Eui2Einterop_p_h__


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
#include "Windows.UI.Core.h"
#include "Windows.Web.UI.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlAcceleratorKeyPressedEventArgs;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs ABI::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlMoveFocusRequestedEventArgs;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs ABI::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlProcess;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess ABI::Windows::Web::UI::Interop::IWebViewControlProcess

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlProcessFactory;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory ABI::Windows::Web::UI::Interop::IWebViewControlProcessFactory

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlProcessOptions;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions ABI::Windows::Web::UI::Interop::IWebViewControlProcessOptions

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlSite;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite ABI::Windows::Web::UI::Interop::IWebViewControlSite

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    interface IWebViewControlSite2;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 ABI::Windows::Web::UI::Interop::IWebViewControlSite2

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    class WebViewControl;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

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


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#define DEF___FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("3e183be4-37d8-5239-b1f0-c06c76296a16"))
IIterator<ABI::Windows::Web::UI::Interop::WebViewControl*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Web.UI.Interop.WebViewControl>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::Web::UI::Interop::WebViewControl*> __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t;
#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Web::UI::IWebViewControl*>
//#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Web::UI::IWebViewControl*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#define DEF___FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("f1028969-d7aa-59d8-8826-4e02a8064515"))
IIterable<ABI::Windows::Web::UI::Interop::WebViewControl*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Web.UI.Interop.WebViewControl>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::Web::UI::Interop::WebViewControl*> __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t;
#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Web::UI::IWebViewControl*>
//#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Web::UI::IWebViewControl*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#define DEF___FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5ecbd5c0-8282-5fe1-ad39-374cde70e0cd"))
IVectorView<ABI::Windows::Web::UI::Interop::WebViewControl*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.Web.UI.Interop.WebViewControl>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::Web::UI::Interop::WebViewControl*> __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t;
#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Web::UI::IWebViewControl*>
//#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::Web::UI::IWebViewControl*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("d61963d6-806d-50a8-a81c-75d9356ad5d7"))
IAsyncOperationCompletedHandler<ABI::Windows::Web::UI::Interop::WebViewControl*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Web.UI.Interop.WebViewControl>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Web::UI::Interop::WebViewControl*> __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Web::UI::IWebViewControl*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Web::UI::IWebViewControl*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#define DEF___FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("ac3d28ac-8362-51c6-b2cc-16f3672758f1"))
IAsyncOperation<ABI::Windows::Web::UI::Interop::WebViewControl*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Web.UI.Interop.WebViewControl>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Web::UI::Interop::WebViewControl*> __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t;
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Web::UI::IWebViewControl*>
//#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Web::UI::IWebViewControl*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("34a6446f-5467-5063-bdc0-7fb0657510d1"))
ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControl*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.Interop.WebViewControl, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControl*,IInspectable*> __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    class WebViewControlAcceleratorKeyPressedEventArgs;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b24e7b5b-b804-5346-97b5-02e6d9b6cba8"))
ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControl*,ABI::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs*, ABI::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.Interop.WebViewControl, Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControl*,ABI::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    class WebViewControlMoveFocusRequestedEventArgs;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("234d40c0-2c51-5128-b919-003f1c0a8a26"))
ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControl*,ABI::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControl*, ABI::Windows::Web::UI::IWebViewControl*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs*, ABI::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.Interop.WebViewControl, Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControl*,ABI::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs*> __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::IWebViewControl*,ABI::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    class WebViewControlProcess;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("0c4182f4-cc4c-55f3-b421-d4e749eb80a1"))
ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControlProcess*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Web::UI::Interop::WebViewControlProcess*, ABI::Windows::Web::UI::Interop::IWebViewControlProcess*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Web.UI.Interop.WebViewControlProcess, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Web::UI::Interop::WebViewControlProcess*,IInspectable*> __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::Interop::IWebViewControlProcess*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Web::UI::Interop::IWebViewControlProcess*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Rect Rect;
            
        } /* Foundation */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace System {
            
            typedef enum VirtualKey : int VirtualKey;
            
        } /* System */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                
                typedef enum CoreAcceleratorKeyEventType : int CoreAcceleratorKeyEventType;
                
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                
                typedef struct CorePhysicalKeyStatus CorePhysicalKeyStatus;
                
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */





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





namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    
                    typedef enum WebViewControlAcceleratorKeyRoutingStage : int WebViewControlAcceleratorKeyRoutingStage;
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    
                    typedef enum WebViewControlMoveFocusReason : int WebViewControlMoveFocusReason;
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    
                    typedef enum WebViewControlProcessCapabilityState : int WebViewControlProcessCapabilityState;
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */












namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    class WebViewControlProcessOptions;
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */












/*
 *
 * Struct Windows.Web.UI.Interop.WebViewControlAcceleratorKeyRoutingStage
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
                namespace Interop {
                    /* [v1_enum, contract] */
                    enum WebViewControlAcceleratorKeyRoutingStage : int
                    {
                        WebViewControlAcceleratorKeyRoutingStage_Tunneling = 0,
                        WebViewControlAcceleratorKeyRoutingStage_Bubbling = 1,
                    };
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Web.UI.Interop.WebViewControlMoveFocusReason
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
                namespace Interop {
                    /* [v1_enum, contract] */
                    enum WebViewControlMoveFocusReason : int
                    {
                        WebViewControlMoveFocusReason_Programmatic = 0,
                        WebViewControlMoveFocusReason_Next = 1,
                        WebViewControlMoveFocusReason_Previous = 2,
                    };
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Web.UI.Interop.WebViewControlProcessCapabilityState
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
                namespace Interop {
                    /* [v1_enum, contract] */
                    enum WebViewControlProcessCapabilityState : int
                    {
                        WebViewControlProcessCapabilityState_Default = 0,
                        WebViewControlProcessCapabilityState_Disabled = 1,
                        WebViewControlProcessCapabilityState_Enabled = 2,
                    };
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs[] = L"Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("77A2A53E-7C74-437D-A290-3AC0D8CD5655"), exclusiveto, contract] */
                    MIDL_INTERFACE("77A2A53E-7C74-437D-A290-3AC0D8CD5655")
                    IWebViewControlAcceleratorKeyPressedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EventType(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Core::CoreAcceleratorKeyEventType * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_VirtualKey(
                            /* [retval, out] */__RPC__out ABI::Windows::System::VirtualKey * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_KeyStatus(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Core::CorePhysicalKeyStatus * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RoutingStage(
                            /* [retval, out] */__RPC__out ABI::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                            /* [in] */::boolean value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlAcceleratorKeyPressedEventArgs=_uuidof(IWebViewControlAcceleratorKeyPressedEventArgs);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlMoveFocusRequestedEventArgs[] = L"Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("6B2A340D-4BD0-405E-B7C1-1E72A492F446"), exclusiveto, contract] */
                    MIDL_INTERFACE("6B2A340D-4BD0-405E-B7C1-1E72A492F446")
                    IWebViewControlMoveFocusRequestedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Reason(
                            /* [retval, out] */__RPC__out ABI::Windows::Web::UI::Interop::WebViewControlMoveFocusReason * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlMoveFocusRequestedEventArgs=_uuidof(IWebViewControlMoveFocusRequestedEventArgs);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlProcess
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlProcess
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlProcess[] = L"Windows.Web.UI.Interop.IWebViewControlProcess";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("02C723EC-98D6-424A-B63E-C6136C36A0F2"), exclusiveto, contract] */
                    MIDL_INTERFACE("02C723EC-98D6-424A-B63E-C6136C36A0F2")
                    IWebViewControlProcess : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ProcessId(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EnterpriseId(
                            /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPrivateNetworkClientServerCapabilityEnabled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE CreateWebViewControlAsync(
                            /* [in] */INT64 hostWindowHandle,
                            /* [in] */ABI::Windows::Foundation::Rect bounds,
                            /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * * operation
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetWebViewControls(
                            /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Terminate(void) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_ProcessExited(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_ProcessExited(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlProcess=_uuidof(IWebViewControlProcess);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlProcessFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlProcess
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlProcessFactory[] = L"Windows.Web.UI.Interop.IWebViewControlProcessFactory";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("47B65CF9-A2D2-453C-B097-F6779D4B8E02"), exclusiveto, contract] */
                    MIDL_INTERFACE("47B65CF9-A2D2-453C-B097-F6779D4B8E02")
                    IWebViewControlProcessFactory : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateWithOptions(
                            /* [in] */__RPC__in_opt ABI::Windows::Web::UI::Interop::IWebViewControlProcessOptions * processOptions,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::UI::Interop::IWebViewControlProcess * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlProcessFactory=_uuidof(IWebViewControlProcessFactory);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlProcessOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlProcessOptions
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlProcessOptions[] = L"Windows.Web.UI.Interop.IWebViewControlProcessOptions";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("1CCA72A7-3BD6-4826-8261-6C8189505D89"), exclusiveto, contract] */
                    MIDL_INTERFACE("1CCA72A7-3BD6-4826-8261-6C8189505D89")
                    IWebViewControlProcessOptions : public IInspectable
                    {
                    public:
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_EnterpriseId(
                            /* [in] */__RPC__in HSTRING value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EnterpriseId(
                            /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PrivateNetworkClientServerCapability(
                            /* [in] */ABI::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PrivateNetworkClientServerCapability(
                            /* [retval, out] */__RPC__out ABI::Windows::Web::UI::Interop::WebViewControlProcessCapabilityState * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlProcessOptions=_uuidof(IWebViewControlProcessOptions);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlSite
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControl
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlSite[] = L"Windows.Web.UI.Interop.IWebViewControlSite";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("133F47C6-12DC-4898-BD47-04967DE648BA"), exclusiveto, contract] */
                    MIDL_INTERFACE("133F47C6-12DC-4898-BD47-04967DE648BA")
                    IWebViewControlSite : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Process(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Web::UI::Interop::IWebViewControlProcess * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Scale(
                            /* [in] */DOUBLE value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Scale(
                            /* [retval, out] */__RPC__out DOUBLE * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Bounds(
                            /* [in] */ABI::Windows::Foundation::Rect value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Bounds(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Rect * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsVisible(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsVisible(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Close(void) = 0;
                        virtual HRESULT STDMETHODCALLTYPE MoveFocus(
                            /* [in] */ABI::Windows::Web::UI::Interop::WebViewControlMoveFocusReason reason
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_MoveFocusRequested(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_MoveFocusRequested(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_AcceleratorKeyPressed(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_AcceleratorKeyPressed(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlSite=_uuidof(IWebViewControlSite);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlSite2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControl
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlSite2[] = L"Windows.Web.UI.Interop.IWebViewControlSite2";
namespace ABI {
    namespace Windows {
        namespace Web {
            namespace UI {
                namespace Interop {
                    /* [object, uuid("D13B2E3F-48EE-4730-8243-D2ED0C05606A"), exclusiveto, contract] */
                    MIDL_INTERFACE("D13B2E3F-48EE-4730-8243-D2ED0C05606A")
                    IWebViewControlSite2 : public IInspectable
                    {
                    public:
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_GotFocus(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_GotFocus(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_LostFocus(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_LostFocus(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IWebViewControlSite2=_uuidof(IWebViewControlSite2);
                    
                } /* Interop */
            } /* UI */
        } /* Web */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControl ** Default Interface **
 *    Windows.Web.UI.Interop.IWebViewControlSite
 *    Windows.Web.UI.IWebViewControl2
 *    Windows.Web.UI.Interop.IWebViewControlSite2
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControl_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControl_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControl[] = L"Windows.Web.UI.Interop.WebViewControl";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlAcceleratorKeyPressedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlAcceleratorKeyPressedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlAcceleratorKeyPressedEventArgs[] = L"Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlMoveFocusRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlMoveFocusRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlMoveFocusRequestedEventArgs[] = L"Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlProcess
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Web.UI.Interop.IWebViewControlProcessFactory interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Type can be activated via RoActivateInstance starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlProcess ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcess_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcess_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlProcess[] = L"Windows.Web.UI.Interop.WebViewControlProcess";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlProcessOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlProcessOptions ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcessOptions_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcessOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlProcessOptions[] = L"Windows.Web.UI.Interop.WebViewControlProcessOptions";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2;

#endif // ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions
#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControl __x_ABI_CWindows_CWeb_CUI_CIWebViewControl;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl_FWD_DEFINED__


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

typedef struct __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl;

interface __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl
{
    CONST_VTBL struct __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

typedef  struct __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CWeb__CUI__CInterop__CWebViewControl **first);

    END_INTERFACE
} __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl;

interface __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl
{
    CONST_VTBL struct __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

typedef struct __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
            /* [in] */ __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl;

interface __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl
{
    CONST_VTBL struct __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl;

typedef struct __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CWeb__CUI__CInterop__CWebViewControl **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl;

interface __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControlVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CIWebViewControl * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



typedef struct __x_ABI_CWindows_CFoundation_CRect __x_ABI_CWindows_CFoundation_CRect;





typedef enum __x_ABI_CWindows_CSystem_CVirtualKey __x_ABI_CWindows_CSystem_CVirtualKey;




typedef enum __x_ABI_CWindows_CUI_CCore_CCoreAcceleratorKeyEventType __x_ABI_CWindows_CUI_CCore_CCoreAcceleratorKeyEventType;


typedef struct __x_ABI_CWindows_CUI_CCore_CCorePhysicalKeyStatus __x_ABI_CWindows_CUI_CCore_CCorePhysicalKeyStatus;





#ifndef ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__
#define ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2 __x_ABI_CWindows_CWeb_CUI_CIWebViewControl2;

#endif // ____x_ABI_CWindows_CWeb_CUI_CIWebViewControl2_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlAcceleratorKeyRoutingStage __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlAcceleratorKeyRoutingStage;


typedef enum __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlMoveFocusReason __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlMoveFocusReason;


typedef enum __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlProcessCapabilityState __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlProcessCapabilityState;























/*
 *
 * Struct Windows.Web.UI.Interop.WebViewControlAcceleratorKeyRoutingStage
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlAcceleratorKeyRoutingStage
{
    WebViewControlAcceleratorKeyRoutingStage_Tunneling = 0,
    WebViewControlAcceleratorKeyRoutingStage_Bubbling = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Web.UI.Interop.WebViewControlMoveFocusReason
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlMoveFocusReason
{
    WebViewControlMoveFocusReason_Programmatic = 0,
    WebViewControlMoveFocusReason_Next = 1,
    WebViewControlMoveFocusReason_Previous = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Web.UI.Interop.WebViewControlProcessCapabilityState
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlProcessCapabilityState
{
    WebViewControlProcessCapabilityState_Default = 0,
    WebViewControlProcessCapabilityState_Disabled = 1,
    WebViewControlProcessCapabilityState_Enabled = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs[] = L"Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs";
/* [object, uuid("77A2A53E-7C74-437D-A290-3AC0D8CD5655"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EventType )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CCore_CCoreAcceleratorKeyEventType * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_VirtualKey )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSystem_CVirtualKey * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_KeyStatus )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CCore_CCorePhysicalKeyStatus * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RoutingStage )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlAcceleratorKeyRoutingStage * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_get_EventType(This,value) \
    ( (This)->lpVtbl->get_EventType(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_get_VirtualKey(This,value) \
    ( (This)->lpVtbl->get_VirtualKey(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_get_KeyStatus(This,value) \
    ( (This)->lpVtbl->get_KeyStatus(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_get_RoutingStage(This,value) \
    ( (This)->lpVtbl->get_RoutingStage(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlAcceleratorKeyPressedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlMoveFocusRequestedEventArgs[] = L"Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs";
/* [object, uuid("6B2A340D-4BD0-405E-B7C1-1E72A492F446"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Reason )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlMoveFocusReason * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_get_Reason(This,value) \
    ( (This)->lpVtbl->get_Reason(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlMoveFocusRequestedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlProcess
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlProcess
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlProcess[] = L"Windows.Web.UI.Interop.IWebViewControlProcess";
/* [object, uuid("02C723EC-98D6-424A-B63E-C6136C36A0F2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ProcessId )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EnterpriseId )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPrivateNetworkClientServerCapabilityEnabled )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *CreateWebViewControlAsync )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [in] */INT64 hostWindowHandle,
        /* [in] */__x_ABI_CWindows_CFoundation_CRect bounds,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CWeb__CUI__CInterop__CWebViewControl * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *GetWebViewControls )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CWeb__CUI__CInterop__CWebViewControl * * result
        );
    HRESULT ( STDMETHODCALLTYPE *Terminate )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_ProcessExited )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControlProcess_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_ProcessExited )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_get_ProcessId(This,value) \
    ( (This)->lpVtbl->get_ProcessId(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_get_EnterpriseId(This,value) \
    ( (This)->lpVtbl->get_EnterpriseId(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_get_IsPrivateNetworkClientServerCapabilityEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPrivateNetworkClientServerCapabilityEnabled(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_CreateWebViewControlAsync(This,hostWindowHandle,bounds,operation) \
    ( (This)->lpVtbl->CreateWebViewControlAsync(This,hostWindowHandle,bounds,operation) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_GetWebViewControls(This,result) \
    ( (This)->lpVtbl->GetWebViewControls(This,result) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_Terminate(This) \
    ( (This)->lpVtbl->Terminate(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_add_ProcessExited(This,handler,token) \
    ( (This)->lpVtbl->add_ProcessExited(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_remove_ProcessExited(This,token) \
    ( (This)->lpVtbl->remove_ProcessExited(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlProcessFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlProcess
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlProcessFactory[] = L"Windows.Web.UI.Interop.IWebViewControlProcessFactory";
/* [object, uuid("47B65CF9-A2D2-453C-B097-F6779D4B8E02"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateWithOptions )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * processOptions,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactoryVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_CreateWithOptions(This,processOptions,result) \
    ( (This)->lpVtbl->CreateWithOptions(This,processOptions,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlProcessOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControlProcessOptions
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlProcessOptions[] = L"Windows.Web.UI.Interop.IWebViewControlProcessOptions";
/* [object, uuid("1CCA72A7-3BD6-4826-8261-6C8189505D89"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptionsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propput] */HRESULT ( STDMETHODCALLTYPE *put_EnterpriseId )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EnterpriseId )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PrivateNetworkClientServerCapability )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
        /* [in] */__x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlProcessCapabilityState value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PrivateNetworkClientServerCapability )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlProcessCapabilityState * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptionsVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptionsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_put_EnterpriseId(This,value) \
    ( (This)->lpVtbl->put_EnterpriseId(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_get_EnterpriseId(This,value) \
    ( (This)->lpVtbl->get_EnterpriseId(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_put_PrivateNetworkClientServerCapability(This,value) \
    ( (This)->lpVtbl->put_PrivateNetworkClientServerCapability(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_get_PrivateNetworkClientServerCapability(This,value) \
    ( (This)->lpVtbl->get_PrivateNetworkClientServerCapability(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcessOptions_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlSite
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControl
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlSite[] = L"Windows.Web.UI.Interop.IWebViewControlSite";
/* [object, uuid("133F47C6-12DC-4898-BD47-04967DE648BA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSiteVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Process )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlProcess * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Scale )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */DOUBLE value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Scale )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Bounds )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CRect value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Bounds )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CRect * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsVisible )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsVisible )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *Close )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This
        );
    HRESULT ( STDMETHODCALLTYPE *MoveFocus )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */__x_ABI_CWindows_CWeb_CUI_CInterop_CWebViewControlMoveFocusReason reason
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_MoveFocusRequested )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlMoveFocusRequestedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_MoveFocusRequested )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_AcceleratorKeyPressed )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_Windows__CWeb__CUI__CInterop__CWebViewControlAcceleratorKeyPressedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_AcceleratorKeyPressed )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSiteVtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSiteVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_get_Process(This,value) \
    ( (This)->lpVtbl->get_Process(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_put_Scale(This,value) \
    ( (This)->lpVtbl->put_Scale(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_get_Scale(This,value) \
    ( (This)->lpVtbl->get_Scale(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_put_Bounds(This,value) \
    ( (This)->lpVtbl->put_Bounds(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_get_Bounds(This,value) \
    ( (This)->lpVtbl->get_Bounds(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_put_IsVisible(This,value) \
    ( (This)->lpVtbl->put_IsVisible(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_get_IsVisible(This,value) \
    ( (This)->lpVtbl->get_IsVisible(This,value) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_Close(This) \
    ( (This)->lpVtbl->Close(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_MoveFocus(This,reason) \
    ( (This)->lpVtbl->MoveFocus(This,reason) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_add_MoveFocusRequested(This,handler,token) \
    ( (This)->lpVtbl->add_MoveFocusRequested(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_remove_MoveFocusRequested(This,token) \
    ( (This)->lpVtbl->remove_MoveFocusRequested(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_add_AcceleratorKeyPressed(This,handler,token) \
    ( (This)->lpVtbl->add_AcceleratorKeyPressed(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_remove_AcceleratorKeyPressed(This,token) \
    ( (This)->lpVtbl->remove_AcceleratorKeyPressed(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Web.UI.Interop.IWebViewControlSite2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Web.UI.Interop.WebViewControl
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Web_UI_Interop_IWebViewControlSite2[] = L"Windows.Web.UI.Interop.IWebViewControlSite2";
/* [object, uuid("D13B2E3F-48EE-4730-8243-D2ED0C05606A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_GotFocus )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_GotFocus )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_LostFocus )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CWeb__CUI__CInterop__CWebViewControl_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_LostFocus )(
        __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2 * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2Vtbl;

interface __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2
{
    CONST_VTBL struct __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_add_GotFocus(This,handler,token) \
    ( (This)->lpVtbl->add_GotFocus(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_remove_GotFocus(This,token) \
    ( (This)->lpVtbl->remove_GotFocus(This,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_add_LostFocus(This,handler,token) \
    ( (This)->lpVtbl->add_LostFocus(This,handler,token) )

#define __x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_remove_LostFocus(This,token) \
    ( (This)->lpVtbl->remove_LostFocus(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2;
#endif /* !defined(____x_ABI_CWindows_CWeb_CUI_CInterop_CIWebViewControlSite2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControl
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.IWebViewControl ** Default Interface **
 *    Windows.Web.UI.Interop.IWebViewControlSite
 *    Windows.Web.UI.IWebViewControl2
 *    Windows.Web.UI.Interop.IWebViewControlSite2
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControl_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControl_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControl[] = L"Windows.Web.UI.Interop.WebViewControl";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlAcceleratorKeyPressedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlAcceleratorKeyPressedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlAcceleratorKeyPressedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlAcceleratorKeyPressedEventArgs[] = L"Windows.Web.UI.Interop.WebViewControlAcceleratorKeyPressedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlMoveFocusRequestedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlMoveFocusRequestedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlMoveFocusRequestedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlMoveFocusRequestedEventArgs[] = L"Windows.Web.UI.Interop.WebViewControlMoveFocusRequestedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlProcess
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via the Windows.Web.UI.Interop.IWebViewControlProcessFactory interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Type can be activated via RoActivateInstance starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlProcess ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcess_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcess_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlProcess[] = L"Windows.Web.UI.Interop.WebViewControlProcess";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Web.UI.Interop.WebViewControlProcessOptions
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Web.UI.Interop.IWebViewControlProcessOptions ** Default Interface **
 *
 * Class Marshaling Behavior:  Standard - Class marshals using the standard marshaler
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcessOptions_DEFINED
#define RUNTIMECLASS_Windows_Web_UI_Interop_WebViewControlProcessOptions_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Web_UI_Interop_WebViewControlProcessOptions[] = L"Windows.Web.UI.Interop.WebViewControlProcessOptions";
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
#endif // __windows2Eweb2Eui2Einterop_p_h__

#endif // __windows2Eweb2Eui2Einterop_h__
