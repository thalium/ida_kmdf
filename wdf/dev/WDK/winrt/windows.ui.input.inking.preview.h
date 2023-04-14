/* Header file automatically generated from windows.ui.input.inking.preview.idl */
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
#ifndef __windows2Eui2Einput2Einking2Epreview_h__
#define __windows2Eui2Einput2Einking2Epreview_h__
#ifndef __windows2Eui2Einput2Einking2Epreview_p_h__
#define __windows2Eui2Einput2Einking2Epreview_p_h__


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
#include "Windows.UI.Composition.h"

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Input {
                namespace Inking {
                    namespace Preview {
                        interface IPalmRejectionDelayZonePreview;
                    } /* Preview */
                } /* Inking */
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview ABI::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview

#endif // ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Input {
                namespace Inking {
                    namespace Preview {
                        interface IPalmRejectionDelayZonePreviewStatics;
                    } /* Preview */
                } /* Inking */
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics ABI::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics

#endif // ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_FWD_DEFINED__


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
            
            typedef struct Rect Rect;
            
        } /* Foundation */
    } /* Windows */} /* ABI */




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
        namespace UI {
            namespace Input {
                namespace Inking {
                    namespace Preview {
                        class PalmRejectionDelayZonePreview;
                    } /* Preview */
                } /* Inking */
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */








/*
 *
 * Interface Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreview[] = L"Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Input {
                namespace Inking {
                    namespace Preview {
                        /* [object, uuid("62B496CB-539D-5343-A65F-41F5300EC70C"), exclusiveto, contract] */
                        MIDL_INTERFACE("62B496CB-539D-5343-A65F-41F5300EC70C")
                        IPalmRejectionDelayZonePreview : public IInspectable
                        {
                        public:
                            
                        };

                        extern MIDL_CONST_ID IID & IID_IPalmRejectionDelayZonePreview=_uuidof(IPalmRejectionDelayZonePreview);
                        
                    } /* Preview */
                } /* Inking */
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview;
#endif /* !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreviewStatics[] = L"Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Input {
                namespace Inking {
                    namespace Preview {
                        /* [object, uuid("CDEF5EE0-93D0-53A9-8F0E-9A379F8F7530"), exclusiveto, contract] */
                        MIDL_INTERFACE("CDEF5EE0-93D0-53A9-8F0E-9A379F8F7530")
                        IPalmRejectionDelayZonePreviewStatics : public IInspectable
                        {
                        public:
                            /* [overload] */virtual HRESULT STDMETHODCALLTYPE CreateForVisual(
                                /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * inputPanelVisual,
                                /* [in] */ABI::Windows::Foundation::Rect inputPanelRect,
                                /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview * * result
                                ) = 0;
                            /* [overload] */virtual HRESULT STDMETHODCALLTYPE CreateForVisualWithViewportClip(
                                /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * inputPanelVisual,
                                /* [in] */ABI::Windows::Foundation::Rect inputPanelRect,
                                /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * viewportVisual,
                                /* [in] */ABI::Windows::Foundation::Rect viewportRect,
                                /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview * * result
                                ) = 0;
                            
                        };

                        extern MIDL_CONST_ID IID & IID_IPalmRejectionDelayZonePreviewStatics=_uuidof(IPalmRejectionDelayZonePreviewStatics);
                        
                    } /* Preview */
                } /* Inking */
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_UI_Input_Inking_Preview_PalmRejectionDelayZonePreview_DEFINED
#define RUNTIMECLASS_Windows_UI_Input_Inking_Preview_PalmRejectionDelayZonePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Input_Inking_Preview_PalmRejectionDelayZonePreview[] = L"Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000






#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview;

#endif // ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics;

#endif // ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIClosable __x_ABI_CWindows_CFoundation_CIClosable;

#endif // ____x_ABI_CWindows_CFoundation_CIClosable_FWD_DEFINED__



typedef struct __x_ABI_CWindows_CFoundation_CRect __x_ABI_CWindows_CFoundation_CRect;




#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVisual __x_ABI_CWindows_CUI_CComposition_CIVisual;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__














/*
 *
 * Interface Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreview[] = L"Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview";
/* [object, uuid("62B496CB-539D-5343-A65F-41F5300EC70C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewVtbl;

interface __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview;
#endif /* !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreviewStatics[] = L"Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics";
/* [object, uuid("CDEF5EE0-93D0-53A9-8F0E-9A379F8F7530"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *CreateForVisual )(
        __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * inputPanelVisual,
        /* [in] */__x_ABI_CWindows_CFoundation_CRect inputPanelRect,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *CreateForVisualWithViewportClip )(
        __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * inputPanelVisual,
        /* [in] */__x_ABI_CWindows_CFoundation_CRect inputPanelRect,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * viewportVisual,
        /* [in] */__x_ABI_CWindows_CFoundation_CRect viewportRect,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreview * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStaticsVtbl;

interface __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_CreateForVisual(This,inputPanelVisual,inputPanelRect,result) \
    ( (This)->lpVtbl->CreateForVisual(This,inputPanelVisual,inputPanelRect,result) )

#define __x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_CreateForVisualWithViewportClip(This,inputPanelVisual,inputPanelRect,viewportVisual,viewportRect,result) \
    ( (This)->lpVtbl->CreateForVisualWithViewportClip(This,inputPanelVisual,inputPanelRect,viewportVisual,viewportRect,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CInput_CInking_CPreview_CIPalmRejectionDelayZonePreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreviewStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Input.Inking.Preview.IPalmRejectionDelayZonePreview ** Default Interface **
 *    Windows.Foundation.IClosable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_UI_Input_Inking_Preview_PalmRejectionDelayZonePreview_DEFINED
#define RUNTIMECLASS_Windows_UI_Input_Inking_Preview_PalmRejectionDelayZonePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Input_Inking_Preview_PalmRejectionDelayZonePreview[] = L"Windows.UI.Input.Inking.Preview.PalmRejectionDelayZonePreview";
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
#endif // __windows2Eui2Einput2Einking2Epreview_p_h__

#endif // __windows2Eui2Einput2Einking2Epreview_h__
