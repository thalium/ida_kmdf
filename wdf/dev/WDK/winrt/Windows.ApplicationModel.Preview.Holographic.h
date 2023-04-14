/* Header file automatically generated from windows.applicationmodel.preview.holographic.idl */
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
#ifndef __windows2Eapplicationmodel2Epreview2Eholographic_h__
#define __windows2Eapplicationmodel2Epreview2Eholographic_h__
#ifndef __windows2Eapplicationmodel2Epreview2Eholographic_p_h__
#define __windows2Eapplicationmodel2Epreview2Eholographic_p_h__


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
#include "Windows.ApplicationModel.Activation.h"
#include "Windows.Foundation.Numerics.h"
#include "Windows.Perception.Spatial.h"

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    interface IHolographicApplicationPreviewStatics;
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics ABI::Windows::ApplicationModel::Preview::Holographic::IHolographicApplicationPreviewStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    interface IHolographicKeyboardPlacementOverridePreview;
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview ABI::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview

#endif // ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    interface IHolographicKeyboardPlacementOverridePreviewStatics;
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics ABI::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreviewStatics

#endif // ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Activation {
                interface IActivatedEventArgs;
            } /* Activation */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs ABI::Windows::ApplicationModel::Activation::IActivatedEventArgs

#endif // ____x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Numerics {
                
                typedef struct Vector2 Vector2;
                
            } /* Numerics */
        } /* Foundation */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Numerics {
                
                typedef struct Vector3 Vector3;
                
            } /* Numerics */
        } /* Foundation */
    } /* Windows */} /* ABI */







namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                class SpatialCoordinateSystem;
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                interface ISpatialCoordinateSystem;
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__









namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    class HolographicKeyboardPlacementOverridePreview;
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */







/*
 *
 * Interface Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics[] = L"Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    /* [object, uuid("FE038691-2A3A-45A9-A208-7BED691919F3"), exclusiveto, contract] */
                    MIDL_INTERFACE("FE038691-2A3A-45A9-A208-7BED691919F3")
                    IHolographicApplicationPreviewStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE IsCurrentViewPresentedOnHolographicDisplay(
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE IsHolographicActivation(
                            /* [in] */__RPC__in_opt ABI::Windows::ApplicationModel::Activation::IActivatedEventArgs * activatedEventArgs,
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IHolographicApplicationPreviewStatics=_uuidof(IHolographicApplicationPreviewStatics);
                    
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview[] = L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    /* [object, uuid("C8A8CE3A-DFDE-5A14-8D5F-182C526DD9C4"), exclusiveto, contract] */
                    MIDL_INTERFACE("C8A8CE3A-DFDE-5A14-8D5F-182C526DD9C4")
                    IHolographicKeyboardPlacementOverridePreview : public IInspectable
                    {
                    public:
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE SetPlacementOverride(
                            /* [in] */__RPC__in_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * coordinateSystem,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 topCenterPosition,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 normal
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE SetPlacementOverrideWithMaxSize(
                            /* [in] */__RPC__in_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * coordinateSystem,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 topCenterPosition,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 normal,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector2 maxSize
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ResetPlacementOverride(void) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IHolographicKeyboardPlacementOverridePreview=_uuidof(IHolographicKeyboardPlacementOverridePreview);
                    
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics[] = L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics";
namespace ABI {
    namespace Windows {
        namespace ApplicationModel {
            namespace Preview {
                namespace Holographic {
                    /* [object, uuid("202E6039-1FF6-5A06-AAC4-A5E24FA3EC4B"), exclusiveto, contract] */
                    MIDL_INTERFACE("202E6039-1FF6-5A06-AAC4-A5E24FA3EC4B")
                    IHolographicKeyboardPlacementOverridePreviewStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IHolographicKeyboardPlacementOverridePreviewStatics=_uuidof(IHolographicKeyboardPlacementOverridePreviewStatics);
                    
                } /* Holographic */
            } /* Preview */
        } /* ApplicationModel */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicApplicationPreview_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicApplicationPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Preview_Holographic_HolographicApplicationPreview[] = L"Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicKeyboardPlacementOverridePreview_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicKeyboardPlacementOverridePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Preview_Holographic_HolographicKeyboardPlacementOverridePreview[] = L"Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview;

#endif // ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics;

#endif // ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs __x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs;

#endif // ____x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs_FWD_DEFINED__






typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector2 __x_ABI_CWindows_CFoundation_CNumerics_CVector2;


typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3 __x_ABI_CWindows_CFoundation_CNumerics_CVector3;







#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem;

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__















/*
 *
 * Interface Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Preview_Holographic_IHolographicApplicationPreviewStatics[] = L"Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics";
/* [object, uuid("FE038691-2A3A-45A9-A208-7BED691919F3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *IsCurrentViewPresentedOnHolographicDisplay )(
        __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *IsHolographicActivation )(
        __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CApplicationModel_CActivation_CIActivatedEventArgs * activatedEventArgs,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_IsCurrentViewPresentedOnHolographicDisplay(This,result) \
    ( (This)->lpVtbl->IsCurrentViewPresentedOnHolographicDisplay(This,result) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_IsHolographicActivation(This,activatedEventArgs,result) \
    ( (This)->lpVtbl->IsHolographicActivation(This,activatedEventArgs,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicApplicationPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreview[] = L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview";
/* [object, uuid("C8A8CE3A-DFDE-5A14-8D5F-182C526DD9C4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *SetPlacementOverride )(
        __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * coordinateSystem,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 topCenterPosition,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 normal
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *SetPlacementOverrideWithMaxSize )(
        __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * coordinateSystem,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 topCenterPosition,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 normal,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector2 maxSize
        );
    HRESULT ( STDMETHODCALLTYPE *ResetPlacementOverride )(
        __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewVtbl;

interface __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_SetPlacementOverride(This,coordinateSystem,topCenterPosition,normal) \
    ( (This)->lpVtbl->SetPlacementOverride(This,coordinateSystem,topCenterPosition,normal) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_SetPlacementOverrideWithMaxSize(This,coordinateSystem,topCenterPosition,normal,maxSize) \
    ( (This)->lpVtbl->SetPlacementOverrideWithMaxSize(This,coordinateSystem,topCenterPosition,normal,maxSize) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_ResetPlacementOverride(This) \
    ( (This)->lpVtbl->ResetPlacementOverride(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_ApplicationModel_Preview_Holographic_IHolographicKeyboardPlacementOverridePreviewStatics[] = L"Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics";
/* [object, uuid("202E6039-1FF6-5A06-AAC4-A5E24FA3EC4B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreview * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStaticsVtbl;

interface __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_GetForCurrentView(This,result) \
    ( (This)->lpVtbl->GetForCurrentView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CApplicationModel_CPreview_CHolographic_CIHolographicKeyboardPlacementOverridePreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Preview.Holographic.IHolographicApplicationPreviewStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#ifndef RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicApplicationPreview_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicApplicationPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Preview_Holographic_HolographicApplicationPreview[] = L"Windows.ApplicationModel.Preview.Holographic.HolographicApplicationPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreviewStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.ApplicationModel.Preview.Holographic.IHolographicKeyboardPlacementOverridePreview ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicKeyboardPlacementOverridePreview_DEFINED
#define RUNTIMECLASS_Windows_ApplicationModel_Preview_Holographic_HolographicKeyboardPlacementOverridePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_ApplicationModel_Preview_Holographic_HolographicKeyboardPlacementOverridePreview[] = L"Windows.ApplicationModel.Preview.Holographic.HolographicKeyboardPlacementOverridePreview";
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
#endif // __windows2Eapplicationmodel2Epreview2Eholographic_p_h__

#endif // __windows2Eapplicationmodel2Epreview2Eholographic_h__
