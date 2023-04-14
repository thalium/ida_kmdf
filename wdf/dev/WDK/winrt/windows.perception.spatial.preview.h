/* Header file automatically generated from windows.perception.spatial.preview.idl */
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
#ifndef __windows2Eperception2Espatial2Epreview_h__
#define __windows2Eperception2Espatial2Epreview_h__
#ifndef __windows2Eperception2Espatial2Epreview_p_h__
#define __windows2Eperception2Espatial2Epreview_p_h__


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
#include "Windows.Foundation.Numerics.h"
#include "Windows.Perception.Spatial.h"

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    interface ISpatialGraphInteropFrameOfReferencePreview;
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview ABI::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    interface ISpatialGraphInteropPreviewStatics;
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics ABI::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    interface ISpatialGraphInteropPreviewStatics2;
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 ABI::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Numerics {
                
                typedef struct Matrix4x4 Matrix4x4;
                
            } /* Numerics */
        } /* Foundation */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Numerics {
                
                typedef struct Quaternion Quaternion;
                
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
        namespace Perception {
            namespace Spatial {
                class SpatialLocator;
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                interface ISpatialLocator;
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator ABI::Windows::Perception::Spatial::ISpatialLocator

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator_FWD_DEFINED__








namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    class SpatialGraphInteropFrameOfReferencePreview;
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */








/*
 *
 * Interface Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview[] = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview";
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    /* [object, uuid("A8271B23-735F-5729-A98E-E64ED189ABC5"), exclusiveto, contract] */
                    MIDL_INTERFACE("A8271B23-735F-5729-A98E-E64ED189ABC5")
                    ISpatialGraphInteropFrameOfReferencePreview : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CoordinateSystem(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NodeId(
                            /* [retval, out] */__RPC__out GUID * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_CoordinateSystemToNodeTransform(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Matrix4x4 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISpatialGraphInteropFrameOfReferencePreview=_uuidof(ISpatialGraphInteropFrameOfReferencePreview);
                    
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview;
#endif /* !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics[] = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics";
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    /* [object, uuid("C042644C-20D8-4ED0-AEF7-6805B8E53F55"), exclusiveto, contract] */
                    MIDL_INTERFACE("C042644C-20D8-4ED0-AEF7-6805B8E53F55")
                    ISpatialGraphInteropPreviewStatics : public IInspectable
                    {
                    public:
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE CreateCoordinateSystemForNode(
                            /* [in] */GUID nodeId,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * * result
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE CreateCoordinateSystemForNodeWithPosition(
                            /* [in] */GUID nodeId,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 relativePosition,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * * result
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE CreateCoordinateSystemForNodeWithPositionAndOrientation(
                            /* [in] */GUID nodeId,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 relativePosition,
                            /* [in] */ABI::Windows::Foundation::Numerics::Quaternion relativeOrientation,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE CreateLocatorForNode(
                            /* [in] */GUID nodeId,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::ISpatialLocator * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISpatialGraphInteropPreviewStatics=_uuidof(ISpatialGraphInteropPreviewStatics);
                    
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2[] = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2";
namespace ABI {
    namespace Windows {
        namespace Perception {
            namespace Spatial {
                namespace Preview {
                    /* [object, uuid("2490B15F-6CBD-4B1E-B765-31E462A32DF2"), exclusiveto, contract] */
                    MIDL_INTERFACE("2490B15F-6CBD-4B1E-B765-31E462A32DF2")
                    ISpatialGraphInteropPreviewStatics2 : public IInspectable
                    {
                    public:
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryCreateFrameOfReference(
                            /* [in] */__RPC__in_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * coordinateSystem,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview * * result
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryCreateFrameOfReferenceWithPosition(
                            /* [in] */__RPC__in_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * coordinateSystem,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 relativePosition,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview * * result
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryCreateFrameOfReferenceWithPositionAndOrientation(
                            /* [in] */__RPC__in_opt ABI::Windows::Perception::Spatial::ISpatialCoordinateSystem * coordinateSystem,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 relativePosition,
                            /* [in] */ABI::Windows::Foundation::Numerics::Quaternion relativeOrientation,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISpatialGraphInteropPreviewStatics2=_uuidof(ISpatialGraphInteropPreviewStatics2);
                    
                } /* Preview */
            } /* Spatial */
        } /* Perception */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2;
#endif /* !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropFrameOfReferencePreview_DEFINED
#define RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropFrameOfReferencePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Perception_Spatial_Preview_SpatialGraphInteropFrameOfReferencePreview[] = L"Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#ifndef RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropPreview_DEFINED
#define RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Perception_Spatial_Preview_SpatialGraphInteropPreview[] = L"Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview;

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics;

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2;

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_FWD_DEFINED__


typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4 __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4;


typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion;


typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3 __x_ABI_CWindows_CFoundation_CNumerics_CVector3;







#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem;

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator_FWD_DEFINED__
#define ____x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator __x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator;

#endif // ____x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator_FWD_DEFINED__















/*
 *
 * Interface Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview[] = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview";
/* [object, uuid("A8271B23-735F-5729-A98E-E64ED189ABC5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreviewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CoordinateSystem )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NodeId )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
        /* [retval, out] */__RPC__out GUID * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_CoordinateSystemToNodeTransform )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CMatrix4x4 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreviewVtbl;

interface __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview
{
    CONST_VTBL struct __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreviewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_get_CoordinateSystem(This,value) \
    ( (This)->lpVtbl->get_CoordinateSystem(This,value) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_get_NodeId(This,value) \
    ( (This)->lpVtbl->get_NodeId(This,value) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_get_CoordinateSystemToNodeTransform(This,value) \
    ( (This)->lpVtbl->get_CoordinateSystemToNodeTransform(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview;
#endif /* !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics[] = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics";
/* [object, uuid("C042644C-20D8-4ED0-AEF7-6805B8E53F55"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *CreateCoordinateSystemForNode )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
        /* [in] */GUID nodeId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *CreateCoordinateSystemForNodeWithPosition )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
        /* [in] */GUID nodeId,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 relativePosition,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *CreateCoordinateSystemForNodeWithPositionAndOrientation )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
        /* [in] */GUID nodeId,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 relativePosition,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CQuaternion relativeOrientation,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateLocatorForNode )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics * This,
        /* [in] */GUID nodeId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialLocator * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStaticsVtbl;

interface __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_CreateCoordinateSystemForNode(This,nodeId,result) \
    ( (This)->lpVtbl->CreateCoordinateSystemForNode(This,nodeId,result) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_CreateCoordinateSystemForNodeWithPosition(This,nodeId,relativePosition,result) \
    ( (This)->lpVtbl->CreateCoordinateSystemForNodeWithPosition(This,nodeId,relativePosition,result) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_CreateCoordinateSystemForNodeWithPositionAndOrientation(This,nodeId,relativePosition,relativeOrientation,result) \
    ( (This)->lpVtbl->CreateCoordinateSystemForNodeWithPositionAndOrientation(This,nodeId,relativePosition,relativeOrientation,result) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_CreateLocatorForNode(This,nodeId,result) \
    ( (This)->lpVtbl->CreateLocatorForNode(This,nodeId,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics;
#endif /* !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2[] = L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2";
/* [object, uuid("2490B15F-6CBD-4B1E-B765-31E462A32DF2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *TryCreateFrameOfReference )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * coordinateSystem,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *TryCreateFrameOfReferenceWithPosition )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * coordinateSystem,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 relativePosition,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *TryCreateFrameOfReferenceWithPositionAndOrientation )(
        __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CPerception_CSpatial_CISpatialCoordinateSystem * coordinateSystem,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 relativePosition,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CQuaternion relativeOrientation,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropFrameOfReferencePreview * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2Vtbl;

interface __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_TryCreateFrameOfReference(This,coordinateSystem,result) \
    ( (This)->lpVtbl->TryCreateFrameOfReference(This,coordinateSystem,result) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_TryCreateFrameOfReferenceWithPosition(This,coordinateSystem,relativePosition,result) \
    ( (This)->lpVtbl->TryCreateFrameOfReferenceWithPosition(This,coordinateSystem,relativePosition,result) )

#define __x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_TryCreateFrameOfReferenceWithPositionAndOrientation(This,coordinateSystem,relativePosition,relativeOrientation,result) \
    ( (This)->lpVtbl->TryCreateFrameOfReferenceWithPositionAndOrientation(This,coordinateSystem,relativePosition,relativeOrientation,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2;
#endif /* !defined(____x_ABI_CWindows_CPerception_CSpatial_CPreview_CISpatialGraphInteropPreviewStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropFrameOfReferencePreview_DEFINED
#define RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropFrameOfReferencePreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Perception_Spatial_Preview_SpatialGraphInteropFrameOfReferencePreview[] = L"Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics interface starting with version 7.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#ifndef RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropPreview_DEFINED
#define RUNTIMECLASS_Windows_Perception_Spatial_Preview_SpatialGraphInteropPreview_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Perception_Spatial_Preview_SpatialGraphInteropPreview[] = L"Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview";
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
#endif // __windows2Eperception2Espatial2Epreview_p_h__

#endif // __windows2Eperception2Espatial2Epreview_h__
