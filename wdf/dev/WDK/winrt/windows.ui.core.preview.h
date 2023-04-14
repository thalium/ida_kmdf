/* Header file automatically generated from windows.ui.core.preview.idl */
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
#ifndef __windows2Eui2Ecore2Epreview_h__
#define __windows2Eui2Ecore2Epreview_h__
#ifndef __windows2Eui2Ecore2Epreview_p_h__
#define __windows2Eui2Ecore2Epreview_p_h__


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
#include "Windows.UI.WindowManagement.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    interface ICoreAppWindowPreview;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview ABI::Windows::UI::Core::Preview::ICoreAppWindowPreview

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    interface ICoreAppWindowPreviewStatics;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics ABI::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    interface ISystemNavigationCloseRequestedPreviewEventArgs;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs ABI::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    interface ISystemNavigationManagerPreview;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview ABI::Windows::UI::Core::Preview::ISystemNavigationManagerPreview

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    interface ISystemNavigationManagerPreviewStatics;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics ABI::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    class SystemNavigationCloseRequestedPreviewEventArgs;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef DEF___FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_USE
#define DEF___FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("01bca043-4d09-59e4-b1b3-a2ce24629e41"))
IEventHandler<ABI::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs*> : IEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs*, ABI::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.EventHandler`1<Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IEventHandler<ABI::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs*> __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_t;
#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs ABI::Windows::Foundation::__FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs ABI::Windows::Foundation::IEventHandler<ABI::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs*>
//#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_t ABI::Windows::Foundation::IEventHandler<ABI::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000



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





namespace ABI {
    namespace Windows {
        namespace UI {
            namespace WindowManagement {
                class AppWindow;
            } /* WindowManagement */
        } /* UI */
    } /* Windows */} /* ABI */

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










namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    class CoreAppWindowPreview;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    class SystemNavigationManagerPreview;
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */












/*
 *
 * Interface Windows.UI.Core.Preview.ICoreAppWindowPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.CoreAppWindowPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ICoreAppWindowPreview[] = L"Windows.UI.Core.Preview.ICoreAppWindowPreview";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    /* [object, uuid("A4F6E665-365E-5FDE-87A5-9543C3A15AA8"), exclusiveto, contract] */
                    MIDL_INTERFACE("A4F6E665-365E-5FDE-87A5-9543C3A15AA8")
                    ICoreAppWindowPreview : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreAppWindowPreview=_uuidof(ICoreAppWindowPreview);
                    
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.CoreAppWindowPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ICoreAppWindowPreviewStatics[] = L"Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    /* [object, uuid("33AC21BE-423B-5DB6-8A8E-4DC87353B75B"), exclusiveto, contract] */
                    MIDL_INTERFACE("33AC21BE-423B-5DB6-8A8E-4DC87353B75B")
                    ICoreAppWindowPreviewStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE GetIdFromWindow(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::WindowManagement::IAppWindow * window,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreAppWindowPreviewStatics=_uuidof(ICoreAppWindowPreviewStatics);
                    
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs[] = L"Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    /* [object, uuid("83D00DE1-CBE5-4F31-8414-361DA046518F"), exclusiveto, contract] */
                    MIDL_INTERFACE("83D00DE1-CBE5-4F31-8414-361DA046518F")
                    ISystemNavigationCloseRequestedPreviewEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                            /* [in] */::boolean value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetDeferral(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Foundation::IDeferral * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISystemNavigationCloseRequestedPreviewEventArgs=_uuidof(ISystemNavigationCloseRequestedPreviewEventArgs);
                    
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Core.Preview.ISystemNavigationManagerPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.SystemNavigationManagerPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ISystemNavigationManagerPreview[] = L"Windows.UI.Core.Preview.ISystemNavigationManagerPreview";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    /* [object, uuid("EC5F0488-6425-4777-A536-CB5634427F0D"), exclusiveto, contract] */
                    MIDL_INTERFACE("EC5F0488-6425-4777-A536-CB5634427F0D")
                    ISystemNavigationManagerPreview : public IInspectable
                    {
                    public:
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_CloseRequested(
                            /* [in] */__RPC__in_opt __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_CloseRequested(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISystemNavigationManagerPreview=_uuidof(ISystemNavigationManagerPreview);
                    
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.SystemNavigationManagerPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ISystemNavigationManagerPreviewStatics[] = L"Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Core {
                namespace Preview {
                    /* [object, uuid("0E971360-DF74-4BCE-84CB-BD1181AC0A71"), exclusiveto, contract] */
                    MIDL_INTERFACE("0E971360-DF74-4BCE-84CB-BD1181AC0A71")
                    ISystemNavigationManagerPreviewStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Core::Preview::ISystemNavigationManagerPreview * * loader
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISystemNavigationManagerPreviewStatics=_uuidof(ISystemNavigationManagerPreviewStatics);
                    
                } /* Preview */
            } /* Core */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.UI.Core.Preview.CoreAppWindowPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Core.Preview.ICoreAppWindowPreview ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Core_Preview_CoreAppWindowPreview_DEFINED
#define RUNTIMECLASS_Windows_UI_Core_Preview_CoreAppWindowPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Core_Preview_CoreAppWindowPreview[] = L"Windows.UI.Core.Preview.CoreAppWindowPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationCloseRequestedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationCloseRequestedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Core_Preview_SystemNavigationCloseRequestedPreviewEventArgs[] = L"Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.UI.Core.Preview.SystemNavigationManagerPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Core.Preview.ISystemNavigationManagerPreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationManagerPreview_DEFINED
#define RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationManagerPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Core_Preview_SystemNavigationManagerPreview[] = L"Windows.UI.Core.Preview.SystemNavigationManagerPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview;

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics;

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs;

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview;

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics;

#endif // ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__

typedef interface __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs;

typedef struct __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs * This,/* [in] */ __RPC__in_opt IInspectable *sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * *e);
    END_INTERFACE
} __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgsVtbl;

interface __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs
{
    CONST_VTBL struct __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_QueryInterface(This,riid,ppvObject)	\
        ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_AddRef(This)	\
        ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_Release(This)	\
        ( (This)->lpVtbl -> Release(This) ) 

#define __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_Invoke(This,sender,e)	\
        ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */


#endif // ____FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


#ifndef ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIDeferral __x_ABI_CWindows_CFoundation_CIDeferral;

#endif // ____x_ABI_CWindows_CFoundation_CIDeferral_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow;

#endif // ____x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow_FWD_DEFINED__























/*
 *
 * Interface Windows.UI.Core.Preview.ICoreAppWindowPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.CoreAppWindowPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ICoreAppWindowPreview[] = L"Windows.UI.Core.Preview.ICoreAppWindowPreview";
/* [object, uuid("A4F6E665-365E-5FDE-87A5-9543C3A15AA8"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewVtbl;

interface __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.CoreAppWindowPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ICoreAppWindowPreviewStatics[] = L"Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics";
/* [object, uuid("33AC21BE-423B-5DB6-8A8E-4DC87353B75B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetIdFromWindow )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CWindowManagement_CIAppWindow * window,
        /* [retval, out] */__RPC__out INT32 * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStaticsVtbl;

interface __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_GetIdFromWindow(This,window,result) \
    ( (This)->lpVtbl->GetIdFromWindow(This,window,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CICoreAppWindowPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs[] = L"Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs";
/* [object, uuid("83D00DE1-CBE5-4F31-8414-361DA046518F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
        /* [in] */boolean value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDeferral )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CFoundation_CIDeferral * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_GetDeferral(This,result) \
    ( (This)->lpVtbl->GetDeferral(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationCloseRequestedPreviewEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Core.Preview.ISystemNavigationManagerPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.SystemNavigationManagerPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ISystemNavigationManagerPreview[] = L"Windows.UI.Core.Preview.ISystemNavigationManagerPreview";
/* [object, uuid("EC5F0488-6425-4777-A536-CB5634427F0D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_CloseRequested )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This,
        /* [in] */__RPC__in_opt __FIEventHandler_1_Windows__CUI__CCore__CPreview__CSystemNavigationCloseRequestedPreviewEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_CloseRequested )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * This,
        /* [in] */EventRegistrationToken token
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewVtbl;

interface __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_add_CloseRequested(This,handler,token) \
    ( (This)->lpVtbl->add_CloseRequested(This,handler,token) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_remove_CloseRequested(This,token) \
    ( (This)->lpVtbl->remove_CloseRequested(This,token) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Core.Preview.SystemNavigationManagerPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Core_Preview_ISystemNavigationManagerPreviewStatics[] = L"Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics";
/* [object, uuid("0E971360-DF74-4BCE-84CB-BD1181AC0A71"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreview * * loader
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStaticsVtbl;

interface __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_GetForCurrentView(This,loader) \
    ( (This)->lpVtbl->GetForCurrentView(This,loader) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CCore_CPreview_CISystemNavigationManagerPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.UI.Core.Preview.CoreAppWindowPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Core.Preview.ICoreAppWindowPreviewStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Core.Preview.ICoreAppWindowPreview ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Core_Preview_CoreAppWindowPreview_DEFINED
#define RUNTIMECLASS_Windows_UI_Core_Preview_CoreAppWindowPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Core_Preview_CoreAppWindowPreview[] = L"Windows.UI.Core.Preview.CoreAppWindowPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Core.Preview.ISystemNavigationCloseRequestedPreviewEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationCloseRequestedPreviewEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationCloseRequestedPreviewEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Core_Preview_SystemNavigationCloseRequestedPreviewEventArgs[] = L"Windows.UI.Core.Preview.SystemNavigationCloseRequestedPreviewEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.UI.Core.Preview.SystemNavigationManagerPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Core.Preview.ISystemNavigationManagerPreviewStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Core.Preview.ISystemNavigationManagerPreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationManagerPreview_DEFINED
#define RUNTIMECLASS_Windows_UI_Core_Preview_SystemNavigationManagerPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Core_Preview_SystemNavigationManagerPreview[] = L"Windows.UI.Core.Preview.SystemNavigationManagerPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000





#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eui2Ecore2Epreview_p_h__

#endif // __windows2Eui2Ecore2Epreview_h__
