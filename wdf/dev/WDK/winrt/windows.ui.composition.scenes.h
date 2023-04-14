/* Header file automatically generated from windows.ui.composition.scenes.idl */
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
#ifndef __windows2Eui2Ecomposition2Escenes_h__
#define __windows2Eui2Ecomposition2Escenes_h__
#ifndef __windows2Eui2Ecomposition2Escenes_p_h__
#define __windows2Eui2Ecomposition2Escenes_p_h__


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
#include "Windows.Graphics.DirectX.h"
#include "Windows.UI.Composition.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneBoundingBox;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox ABI::Windows::UI::Composition::Scenes::ISceneBoundingBox

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneComponent;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent ABI::Windows::UI::Composition::Scenes::ISceneComponent

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneComponentCollection;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection ABI::Windows::UI::Composition::Scenes::ISceneComponentCollection

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneComponentFactory;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory ABI::Windows::UI::Composition::Scenes::ISceneComponentFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMaterial;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial ABI::Windows::UI::Composition::Scenes::ISceneMaterial

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMaterialFactory;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory ABI::Windows::UI::Composition::Scenes::ISceneMaterialFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMaterialInput;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMaterialInputFactory;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory ABI::Windows::UI::Composition::Scenes::ISceneMaterialInputFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMesh;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh ABI::Windows::UI::Composition::Scenes::ISceneMesh

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMeshMaterialAttributeMap;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap ABI::Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMeshRendererComponent;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent ABI::Windows::UI::Composition::Scenes::ISceneMeshRendererComponent

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMeshRendererComponentStatics;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics ABI::Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMeshStatics;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics ABI::Windows::UI::Composition::Scenes::ISceneMeshStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMetallicRoughnessMaterial;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial ABI::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneMetallicRoughnessMaterialStatics;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics ABI::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneModelTransform;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform ABI::Windows::UI::Composition::Scenes::ISceneModelTransform

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneNode;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode ABI::Windows::UI::Composition::Scenes::ISceneNode

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneNodeCollection;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection ABI::Windows::UI::Composition::Scenes::ISceneNodeCollection

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneNodeStatics;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics ABI::Windows::UI::Composition::Scenes::ISceneNodeStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneObject;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject ABI::Windows::UI::Composition::Scenes::ISceneObject

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneObjectFactory;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory ABI::Windows::UI::Composition::Scenes::ISceneObjectFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface IScenePbrMaterial;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial ABI::Windows::UI::Composition::Scenes::IScenePbrMaterial

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface IScenePbrMaterialFactory;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory ABI::Windows::UI::Composition::Scenes::IScenePbrMaterialFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneRendererComponent;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent ABI::Windows::UI::Composition::Scenes::ISceneRendererComponent

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneRendererComponentFactory;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory ABI::Windows::UI::Composition::Scenes::ISceneRendererComponentFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneSurfaceMaterialInput;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput ABI::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneSurfaceMaterialInputStatics;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics ABI::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneVisual;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual ABI::Windows::UI::Composition::Scenes::ISceneVisual

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    interface ISceneVisualStatics;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics ABI::Windows::UI::Composition::Scenes::ISceneVisualStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    enum SceneAttributeSemantic : int;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


#ifndef DEF___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#define DEF___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("55ef41a2-86b4-5d95-9d2c-747f340779a9"))
IKeyValuePair<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> : IKeyValuePair_impl<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.UI.Composition.Scenes.SceneAttributeSemantic>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IKeyValuePair<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t;
#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>
//#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE */





#ifndef DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#define DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("6e8c9202-4878-50ae-878e-48a303caf1f8"))
IIterator<__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic*> : IIterator_impl<__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.UI.Composition.Scenes.SceneAttributeSemantic>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic*> __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t;
#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::__FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>*>
//#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE */





#ifndef DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#define DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("a3e30221-7ca2-5a3c-a54a-378fee7369cc"))
IIterable<__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic*> : IIterable_impl<__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.Foundation.Collections.IKeyValuePair`2<String, Windows.UI.Composition.Scenes.SceneAttributeSemantic>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<__FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic*> __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t;
#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::__FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>*>
//#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::Foundation::Collections::IKeyValuePair<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneComponent;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("c819527f-80b2-5b44-a3a2-368c1d359f8f"))
IIterator<ABI::Windows::UI::Composition::Scenes::SceneComponent*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneComponent*, ABI::Windows::UI::Composition::Scenes::ISceneComponent*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.Scenes.SceneComponent>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::Scenes::SceneComponent*> __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t;
#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
//#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("9c5148db-05a5-505a-bb14-a0e5dfbb2cd4"))
IIterable<ABI::Windows::UI::Composition::Scenes::SceneComponent*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneComponent*, ABI::Windows::UI::Composition::Scenes::ISceneComponent*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.Scenes.SceneComponent>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::Scenes::SceneComponent*> __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t;
#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
//#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneNode;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b6d9261d-6a3a-5ca4-bf99-9b7efe4d0f88"))
IIterator<ABI::Windows::UI::Composition::Scenes::SceneNode*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneNode*, ABI::Windows::UI::Composition::Scenes::ISceneNode*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.Scenes.SceneNode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::Scenes::SceneNode*> __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_t;
#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
//#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("db4730e4-f364-576b-878e-59a7c459a752"))
IIterable<ABI::Windows::UI::Composition::Scenes::SceneNode*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneNode*, ABI::Windows::UI::Composition::Scenes::ISceneNode*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.Scenes.SceneNode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::Scenes::SceneNode*> __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_t;
#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
//#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



#ifndef DEF___FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#define DEF___FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("10693bb4-d94c-5b35-8aea-f43df6603800"))
IMapView<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> : IMapView_impl<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMapView`2<String, Windows.UI.Composition.Scenes.SceneAttributeSemantic>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMapView<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t;
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::__FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::IMapView<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>
//#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t ABI::Windows::Foundation::Collections::IMapView<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE */





#ifndef DEF___FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#define DEF___FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("41f50f14-9a3c-5240-b042-1bff02e57028"))
IMap<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> : IMap_impl<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IMap`2<String, Windows.UI.Composition.Scenes.SceneAttributeSemantic>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IMap<HSTRING,enum ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic> __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t;
#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::__FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic ABI::Windows::Foundation::Collections::IMap<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>
//#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_t ABI::Windows::Foundation::Collections::IMap<HSTRING,ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_USE */




#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#define DEF___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("17cceac1-fe0a-535d-91d3-a53431e03ed2"))
IVectorView<ABI::Windows::UI::Composition::Scenes::SceneComponent*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneComponent*, ABI::Windows::UI::Composition::Scenes::ISceneComponent*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.Composition.Scenes.SceneComponent>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::Composition::Scenes::SceneComponent*> __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t;
#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
//#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#define DEF___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b5871458-c28c-50c9-acd8-76e7871937fb"))
IVectorView<ABI::Windows::UI::Composition::Scenes::SceneNode*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneNode*, ABI::Windows::UI::Composition::Scenes::ISceneNode*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.Composition.Scenes.SceneNode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::Composition::Scenes::SceneNode*> __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_t;
#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
//#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#define DEF___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("daad0f31-c450-5060-9732-f02c885e9b3f"))
IVector<ABI::Windows::UI::Composition::Scenes::SceneComponent*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneComponent*, ABI::Windows::UI::Composition::Scenes::ISceneComponent*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<Windows.UI.Composition.Scenes.SceneComponent>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<ABI::Windows::UI::Composition::Scenes::SceneComponent*> __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t;
#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::__FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent ABI::Windows::Foundation::Collections::IVector<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
//#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_t ABI::Windows::Foundation::Collections::IVector<ABI::Windows::UI::Composition::Scenes::ISceneComponent*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef DEF___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#define DEF___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("732596a0-6d36-5a59-8a0b-8ff16142b893"))
IVector<ABI::Windows::UI::Composition::Scenes::SceneNode*> : IVector_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Scenes::SceneNode*, ABI::Windows::UI::Composition::Scenes::ISceneNode*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVector`1<Windows.UI.Composition.Scenes.SceneNode>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVector<ABI::Windows::UI::Composition::Scenes::SceneNode*> __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_t;
#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::__FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode ABI::Windows::Foundation::Collections::IVector<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
//#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_t ABI::Windows::Foundation::Collections::IVector<ABI::Windows::UI::Composition::Scenes::ISceneNode*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000



namespace ABI {
    namespace Windows {
        namespace Foundation {
            class MemoryBuffer;
        } /* Foundation */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IMemoryBuffer;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIMemoryBuffer ABI::Windows::Foundation::IMemoryBuffer

#endif // ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__




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
        namespace Foundation {
            namespace Numerics {
                
                typedef struct Vector4 Vector4;
                
            } /* Numerics */
        } /* Foundation */
    } /* Windows */} /* ABI */







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
            namespace DirectX {
                
                typedef enum DirectXPrimitiveTopology : int DirectXPrimitiveTopology;
                
            } /* DirectX */
        } /* Graphics */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                
                typedef enum CompositionBitmapInterpolationMode : int CompositionBitmapInterpolationMode;
                
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                class Compositor;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface ICompositor;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CICompositor ABI::Windows::UI::Composition::ICompositor

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositionSurface_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositionSurface_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface ICompositionSurface;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CICompositionSurface ABI::Windows::UI::Composition::ICompositionSurface

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositionSurface_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    
                    typedef enum SceneAlphaMode : int SceneAlphaMode;
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    
                    typedef enum SceneAttributeSemantic : int SceneAttributeSemantic;
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    
                    typedef enum SceneComponentType : int SceneComponentType;
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    
                    typedef enum SceneWrappingMode : int SceneWrappingMode;
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */






























namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneBoundingBox;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneComponentCollection;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneMaterial;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneMaterialInput;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneMesh;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneMeshMaterialAttributeMap;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneMeshRendererComponent;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneMetallicRoughnessMaterial;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneModelTransform;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneNodeCollection;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneObject;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class ScenePbrMaterial;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneRendererComponent;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneSurfaceMaterialInput;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    class SceneVisual;
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */












/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneAlphaMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [v1_enum, contract] */
                    enum SceneAlphaMode : int
                    {
                        SceneAlphaMode_Opaque = 0,
                        SceneAlphaMode_AlphaTest = 1,
                        SceneAlphaMode_Blend = 2,
                    };
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneAttributeSemantic
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [v1_enum, contract] */
                    enum SceneAttributeSemantic : int
                    {
                        SceneAttributeSemantic_Index = 0,
                        SceneAttributeSemantic_Vertex = 1,
                        SceneAttributeSemantic_Normal = 2,
                        SceneAttributeSemantic_TexCoord0 = 3,
                        SceneAttributeSemantic_TexCoord1 = 4,
                        SceneAttributeSemantic_Color = 5,
                        SceneAttributeSemantic_Tangent = 6,
                    };
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneComponentType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [v1_enum, contract] */
                    enum SceneComponentType : int
                    {
                        SceneComponentType_MeshRendererComponent = 0,
                    };
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneWrappingMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [v1_enum, contract] */
                    enum SceneWrappingMode : int
                    {
                        SceneWrappingMode_ClampToEdge = 0,
                        SceneWrappingMode_MirroredRepeat = 1,
                        SceneWrappingMode_Repeat = 2,
                    };
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneBoundingBox
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneBoundingBox
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneBoundingBox[] = L"Windows.UI.Composition.Scenes.ISceneBoundingBox";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("5D8FFC70-C618-4083-8251-9962593114AA"), exclusiveto, contract] */
                    MIDL_INTERFACE("5D8FFC70-C618-4083-8251-9962593114AA")
                    ISceneBoundingBox : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Center(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Extents(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Max(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Min(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Size(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneBoundingBox=_uuidof(ISceneBoundingBox);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneComponent[] = L"Windows.UI.Composition.Scenes.ISceneComponent";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("AE20FC96-226C-44BD-95CB-DD5ED9EBE9A5"), exclusiveto, contract] */
                    MIDL_INTERFACE("AE20FC96-226C-44BD-95CB-DD5ED9EBE9A5")
                    ISceneComponent : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ComponentType(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Scenes::SceneComponentType * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneComponent=_uuidof(ISceneComponent);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneComponentCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneComponentCollection
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneComponentCollection[] = L"Windows.UI.Composition.Scenes.ISceneComponentCollection";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("C483791C-5F46-45E4-B666-A3D2259F9B2E"), exclusiveto, contract] */
                    MIDL_INTERFACE("C483791C-5F46-45E4-B666-A3D2259F9B2E")
                    ISceneComponentCollection : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneComponentCollection=_uuidof(ISceneComponentCollection);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneComponentFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneComponentFactory[] = L"Windows.UI.Composition.Scenes.ISceneComponentFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("5FBC5574-DDD8-5889-AB5B-D8FA716E7C9E"), exclusiveto, contract] */
                    MIDL_INTERFACE("5FBC5574-DDD8-5889-AB5B-D8FA716E7C9E")
                    ISceneComponentFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneComponentFactory=_uuidof(ISceneComponentFactory);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterial[] = L"Windows.UI.Composition.Scenes.ISceneMaterial";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("8CA74B7C-30DF-4E07-9490-37875AF1A123"), exclusiveto, contract] */
                    MIDL_INTERFACE("8CA74B7C-30DF-4E07-9490-37875AF1A123")
                    ISceneMaterial : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMaterial=_uuidof(ISceneMaterial);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterialFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterialFactory[] = L"Windows.UI.Composition.Scenes.ISceneMaterialFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("67536C19-A707-5254-A495-7FDC799893B9"), exclusiveto, contract] */
                    MIDL_INTERFACE("67536C19-A707-5254-A495-7FDC799893B9")
                    ISceneMaterialFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMaterialFactory=_uuidof(ISceneMaterialFactory);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterialInput[] = L"Windows.UI.Composition.Scenes.ISceneMaterialInput";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("422A1642-1EF1-485C-97E9-AE6F95AD812F"), exclusiveto, contract] */
                    MIDL_INTERFACE("422A1642-1EF1-485C-97E9-AE6F95AD812F")
                    ISceneMaterialInput : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMaterialInput=_uuidof(ISceneMaterialInput);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterialInputFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterialInputFactory[] = L"Windows.UI.Composition.Scenes.ISceneMaterialInputFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("A88FEB74-7D0A-5E4C-A748-1015AF9CA74F"), exclusiveto, contract] */
                    MIDL_INTERFACE("A88FEB74-7D0A-5E4C-A748-1015AF9CA74F")
                    ISceneMaterialInputFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMaterialInputFactory=_uuidof(ISceneMaterialInputFactory);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMesh
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMesh
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMesh[] = L"Windows.UI.Composition.Scenes.ISceneMesh";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("EE9A1530-1155-4C0C-92BD-40020CF78347"), exclusiveto, contract] */
                    MIDL_INTERFACE("EE9A1530-1155-4C0C-92BD-40020CF78347")
                    ISceneMesh : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Bounds(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneBoundingBox * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PrimitiveTopology(
                            /* [retval, out] */__RPC__out ABI::Windows::Graphics::DirectX::DirectXPrimitiveTopology * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PrimitiveTopology(
                            /* [in] */ABI::Windows::Graphics::DirectX::DirectXPrimitiveTopology value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE FillMeshAttribute(
                            /* [in] */ABI::Windows::UI::Composition::Scenes::SceneAttributeSemantic semantic,
                            /* [in] */ABI::Windows::Graphics::DirectX::DirectXPixelFormat format,
                            /* [in] */__RPC__in_opt ABI::Windows::Foundation::IMemoryBuffer * memory
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMesh=_uuidof(ISceneMesh);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshMaterialAttributeMap[] = L"Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("CE843171-3D43-4855-AA69-31FF988D049D"), exclusiveto, contract] */
                    MIDL_INTERFACE("CE843171-3D43-4855-AA69-31FF988D049D")
                    ISceneMeshMaterialAttributeMap : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMeshMaterialAttributeMap=_uuidof(ISceneMeshMaterialAttributeMap);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMeshRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent[] = L"Windows.UI.Composition.Scenes.ISceneMeshRendererComponent";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("9929F7E3-6364-477E-98FE-74ED9FD4C2DE"), exclusiveto, contract] */
                    MIDL_INTERFACE("9929F7E3-6364-477E-98FE-74ED9FD4C2DE")
                    ISceneMeshRendererComponent : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Material(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterial * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Material(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterial * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Mesh(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMesh * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Mesh(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMesh * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UVMappings(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMeshRendererComponent=_uuidof(ISceneMeshRendererComponent);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMeshRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshRendererComponentStatics[] = L"Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("4954F37A-4459-4521-BD6E-2B38B8D711EA"), exclusiveto, contract] */
                    MIDL_INTERFACE("4954F37A-4459-4521-BD6E-2B38B8D711EA")
                    ISceneMeshRendererComponentStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMeshRendererComponent * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMeshRendererComponentStatics=_uuidof(ISceneMeshRendererComponentStatics);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMesh
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshStatics[] = L"Windows.UI.Composition.Scenes.ISceneMeshStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("8412316C-7B57-473F-966B-81DC277B1751"), exclusiveto, contract] */
                    MIDL_INTERFACE("8412316C-7B57-473F-966B-81DC277B1751")
                    ISceneMeshStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMesh * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMeshStatics=_uuidof(ISceneMeshStatics);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial[] = L"Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("C1D91446-799C-429E-A4E4-5DA645F18E61"), exclusiveto, contract] */
                    MIDL_INTERFACE("C1D91446-799C-429E-A4E4-5DA645F18E61")
                    ISceneMetallicRoughnessMaterial : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BaseColorInput(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BaseColorInput(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BaseColorFactor(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector4 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BaseColorFactor(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector4 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MetallicFactor(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MetallicFactor(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MetallicRoughnessInput(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MetallicRoughnessInput(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RoughnessFactor(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RoughnessFactor(
                            /* [in] */FLOAT value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMetallicRoughnessMaterial=_uuidof(ISceneMetallicRoughnessMaterial);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterialStatics[] = L"Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("3BDDCA50-6D9D-4531-8DC4-B27E3E49B7AB"), exclusiveto, contract] */
                    MIDL_INTERFACE("3BDDCA50-6D9D-4531-8DC4-B27E3E49B7AB")
                    ISceneMetallicRoughnessMaterialStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneMetallicRoughnessMaterialStatics=_uuidof(ISceneMetallicRoughnessMaterialStatics);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneModelTransform
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneModelTransform
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneModelTransform[] = L"Windows.UI.Composition.Scenes.ISceneModelTransform";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("C05576C2-32B1-4269-980D-B98537100AE4"), exclusiveto, contract] */
                    MIDL_INTERFACE("C05576C2-32B1-4269-980D-B98537100AE4")
                    ISceneModelTransform : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Orientation(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Quaternion * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Orientation(
                            /* [in] */ABI::Windows::Foundation::Numerics::Quaternion value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RotationAngle(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RotationAngle(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RotationAngleInDegrees(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RotationAngleInDegrees(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RotationAxis(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RotationAxis(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Scale(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Scale(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Translation(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Translation(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneModelTransform=_uuidof(ISceneModelTransform);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneNode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneNode
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneNode[] = L"Windows.UI.Composition.Scenes.ISceneNode";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("ACF2C247-F307-4581-9C41-AF2E29C3B016"), exclusiveto, contract] */
                    MIDL_INTERFACE("ACF2C247-F307-4581-9C41-AF2E29C3B016")
                    ISceneNode : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Children(
                            /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Components(
                            /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Parent(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneNode * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Transform(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneModelTransform * * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE FindFirstComponentOfType(
                            /* [in] */ABI::Windows::UI::Composition::Scenes::SceneComponentType value,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneComponent * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneNode=_uuidof(ISceneNode);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneNodeCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneNodeCollection
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneNodeCollection[] = L"Windows.UI.Composition.Scenes.ISceneNodeCollection";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("29ADA101-2DD9-4332-BE63-60D2CF4269F2"), exclusiveto, contract] */
                    MIDL_INTERFACE("29ADA101-2DD9-4332-BE63-60D2CF4269F2")
                    ISceneNodeCollection : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneNodeCollection=_uuidof(ISceneNodeCollection);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneNodeStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneNode
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneNodeStatics[] = L"Windows.UI.Composition.Scenes.ISceneNodeStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("579A0FAA-BE9D-4210-908C-93D15FEED0B7"), exclusiveto, contract] */
                    MIDL_INTERFACE("579A0FAA-BE9D-4210-908C-93D15FEED0B7")
                    ISceneNodeStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneNode * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneNodeStatics=_uuidof(ISceneNodeStatics);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneObject
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneObject
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneObject[] = L"Windows.UI.Composition.Scenes.ISceneObject";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("1E94249B-0F1B-49EB-A819-877D8450005B"), exclusiveto, contract] */
                    MIDL_INTERFACE("1E94249B-0F1B-49EB-A819-877D8450005B")
                    ISceneObject : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneObject=_uuidof(ISceneObject);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneObjectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneObject
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneObjectFactory[] = L"Windows.UI.Composition.Scenes.ISceneObjectFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("14FE799A-33E4-52EF-956C-44229D21F2C1"), exclusiveto, contract] */
                    MIDL_INTERFACE("14FE799A-33E4-52EF-956C-44229D21F2C1")
                    ISceneObjectFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneObjectFactory=_uuidof(ISceneObjectFactory);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.IScenePbrMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.ScenePbrMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_IScenePbrMaterial[] = L"Windows.UI.Composition.Scenes.IScenePbrMaterial";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("AAB6EBBE-D680-46DF-8294-B6800A9F95E7"), exclusiveto, contract] */
                    MIDL_INTERFACE("AAB6EBBE-D680-46DF-8294-B6800A9F95E7")
                    IScenePbrMaterial : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AlphaCutoff(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AlphaCutoff(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AlphaMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Scenes::SceneAlphaMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_AlphaMode(
                            /* [in] */ABI::Windows::UI::Composition::Scenes::SceneAlphaMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EmissiveInput(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_EmissiveInput(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_EmissiveFactor(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_EmissiveFactor(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsDoubleSided(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsDoubleSided(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NormalInput(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_NormalInput(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NormalScale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_NormalScale(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OcclusionInput(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_OcclusionInput(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneMaterialInput * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OcclusionStrength(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_OcclusionStrength(
                            /* [in] */FLOAT value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IScenePbrMaterial=_uuidof(IScenePbrMaterial);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.IScenePbrMaterialFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.ScenePbrMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_IScenePbrMaterialFactory[] = L"Windows.UI.Composition.Scenes.IScenePbrMaterialFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("2E3F3DFE-0B85-5727-B5BE-B7D3CBAC37FA"), exclusiveto, contract] */
                    MIDL_INTERFACE("2E3F3DFE-0B85-5727-B5BE-B7D3CBAC37FA")
                    IScenePbrMaterialFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IScenePbrMaterialFactory=_uuidof(IScenePbrMaterialFactory);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneRendererComponent[] = L"Windows.UI.Composition.Scenes.ISceneRendererComponent";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("F1ACB857-CF4F-4025-9B25-A2D1944CF507"), exclusiveto, contract] */
                    MIDL_INTERFACE("F1ACB857-CF4F-4025-9B25-A2D1944CF507")
                    ISceneRendererComponent : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneRendererComponent=_uuidof(ISceneRendererComponent);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneRendererComponentFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneRendererComponentFactory[] = L"Windows.UI.Composition.Scenes.ISceneRendererComponentFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("1DB6ED6C-AA2C-5967-9035-56352DC69658"), exclusiveto, contract] */
                    MIDL_INTERFACE("1DB6ED6C-AA2C-5967-9035-56352DC69658")
                    ISceneRendererComponentFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneRendererComponentFactory=_uuidof(ISceneRendererComponentFactory);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput[] = L"Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("9937DA5C-A9CA-4CFC-B3AA-088356518742"), exclusiveto, contract] */
                    MIDL_INTERFACE("9937DA5C-A9CA-4CFC-B3AA-088356518742")
                    ISceneSurfaceMaterialInput : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BitmapInterpolationMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::CompositionBitmapInterpolationMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_BitmapInterpolationMode(
                            /* [in] */ABI::Windows::UI::Composition::CompositionBitmapInterpolationMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Surface(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::ICompositionSurface * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Surface(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositionSurface * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WrappingUMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Scenes::SceneWrappingMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_WrappingUMode(
                            /* [in] */ABI::Windows::UI::Composition::Scenes::SceneWrappingMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WrappingVMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Scenes::SceneWrappingMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_WrappingVMode(
                            /* [in] */ABI::Windows::UI::Composition::Scenes::SceneWrappingMode value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneSurfaceMaterialInput=_uuidof(ISceneSurfaceMaterialInput);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInputStatics[] = L"Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("5A2394D3-6429-4589-BBCF-B84F4F3CFBFE"), exclusiveto, contract] */
                    MIDL_INTERFACE("5A2394D3-6429-4589-BBCF-B84F4F3CFBFE")
                    ISceneSurfaceMaterialInputStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneSurfaceMaterialInputStatics=_uuidof(ISceneSurfaceMaterialInputStatics);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneVisual
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneVisual
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneVisual[] = L"Windows.UI.Composition.Scenes.ISceneVisual";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("8E672C1E-D734-47B1-BE14-3D694FFA4301"), exclusiveto, contract] */
                    MIDL_INTERFACE("8E672C1E-D734-47B1-BE14-3D694FFA4301")
                    ISceneVisual : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Root(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneNode * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Root(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Scenes::ISceneNode * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneVisual=_uuidof(ISceneVisual);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneVisualStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneVisual
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneVisualStatics[] = L"Windows.UI.Composition.Scenes.ISceneVisualStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Scenes {
                    /* [object, uuid("B8347E9A-50AA-4527-8D34-DE4CB8EA88B4"), exclusiveto, contract] */
                    MIDL_INTERFACE("B8347E9A-50AA-4527-8D34-DE4CB8EA88B4")
                    ISceneVisualStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Scenes::ISceneVisual * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ISceneVisualStatics=_uuidof(ISceneVisualStatics);
                    
                } /* Scenes */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneBoundingBox
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneBoundingBox ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneBoundingBox_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneBoundingBox_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneBoundingBox[] = L"Windows.UI.Composition.Scenes.SceneBoundingBox";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneComponent ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponent_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponent_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneComponent[] = L"Windows.UI.Composition.Scenes.SceneComponent";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneComponentCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneComponentCollection
 *    Windows.Foundation.Collections.IVector_1_Windows.UI.Composition.Scenes.SceneComponent ** Default Interface **
 *    Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Scenes.SceneComponent
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponentCollection_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponentCollection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneComponentCollection[] = L"Windows.UI.Composition.Scenes.SceneComponentCollection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMaterial ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterial_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterial_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMaterial[] = L"Windows.UI.Composition.Scenes.SceneMaterial";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMaterialInput ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterialInput_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterialInput_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMaterialInput[] = L"Windows.UI.Composition.Scenes.SceneMaterialInput";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMesh
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneMeshStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMesh ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMesh_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMesh_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMesh[] = L"Windows.UI.Composition.Scenes.SceneMesh";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap ** Default Interface **
 *    Windows.Foundation.Collections.IMap_2_HSTRING,Windows.UI.Composition.Scenes.SceneAttributeSemantic
 *    Windows.Foundation.Collections.IIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshMaterialAttributeMap_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshMaterialAttributeMap_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMeshMaterialAttributeMap[] = L"Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMeshRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMeshRendererComponent ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshRendererComponent_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshRendererComponent_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMeshRendererComponent[] = L"Windows.UI.Composition.Scenes.SceneMeshRendererComponent";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMetallicRoughnessMaterial_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMetallicRoughnessMaterial_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMetallicRoughnessMaterial[] = L"Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneModelTransform
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneModelTransform ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneModelTransform_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneModelTransform_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneModelTransform[] = L"Windows.UI.Composition.Scenes.SceneModelTransform";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneNode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneNodeStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneNode ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNode_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNode_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneNode[] = L"Windows.UI.Composition.Scenes.SceneNode";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneNodeCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneNodeCollection
 *    Windows.Foundation.Collections.IVector_1_Windows.UI.Composition.Scenes.SceneNode ** Default Interface **
 *    Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Scenes.SceneNode
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNodeCollection_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNodeCollection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneNodeCollection[] = L"Windows.UI.Composition.Scenes.SceneNodeCollection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneObject
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneObject ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneObject_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneObject_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneObject[] = L"Windows.UI.Composition.Scenes.SceneObject";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.ScenePbrMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.IScenePbrMaterial ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_ScenePbrMaterial_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_ScenePbrMaterial_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_ScenePbrMaterial[] = L"Windows.UI.Composition.Scenes.ScenePbrMaterial";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneRendererComponent ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneRendererComponent_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneRendererComponent_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneRendererComponent[] = L"Windows.UI.Composition.Scenes.SceneRendererComponent";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneSurfaceMaterialInput_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneSurfaceMaterialInput_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneSurfaceMaterialInput[] = L"Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneVisual
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneVisualStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneVisual ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneVisual_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneVisual_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneVisual[] = L"Windows.UI.Composition.Scenes.SceneVisual";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions
enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic;
#if !defined(____FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__)
#define ____FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__

typedef interface __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

typedef struct __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Key )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__out HSTRING *key);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__deref_out_opt enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic *value);
    END_INTERFACE
} __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl;

interface __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
{
    CONST_VTBL struct __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_get_Key(This,key)	\
    ( (This)->lpVtbl -> get_Key(This,key) ) 

#define __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__



#if !defined(____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__)
#define ____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__

typedef interface __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

typedef struct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__out __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl;

interface __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
{
    CONST_VTBL struct __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__



#if !defined(____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__)
#define ____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__

typedef interface __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

typedef  struct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic **first);

    END_INTERFACE
} __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl;

interface __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
{
    CONST_VTBL struct __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneComponent **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CScenes__CSceneNode **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if !defined(____FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__)
#define ____FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__

typedef interface __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

typedef struct __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,/* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ __RPC__in HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic *value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [in] */ __RPC__in HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *Split )(__RPC__in __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,/* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic **firstPartition,
        /* [out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic **secondPartition);
    END_INTERFACE
} __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl;

interface __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
{
    CONST_VTBL struct __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 
#define __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Split(This,firstPartition,secondPartition)	\
    ( (This)->lpVtbl -> Split(This,firstPartition,secondPartition) ) 
#endif /* COBJMACROS */


#endif // ____FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__



#if !defined(____FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__)
#define ____FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__

typedef interface __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic;

typedef struct __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *Lookup )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ HSTRING key,
        /* [retval][out] */ __RPC__deref_out_opt enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic **value);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__out unsigned int *size);
    HRESULT ( STDMETHODCALLTYPE *HasKey )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [in] */ HSTRING key, /* [retval][out] */ __RPC__out boolean *found);
    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This, /* [retval][out] */ __RPC__deref_out_opt __FIMapView_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic **view);
    HRESULT ( STDMETHODCALLTYPE *Insert )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,
        /* [in] */ HSTRING key,
        /* [in] */ __RPC__in_opt enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic *value,
        /* [retval][out] */ __RPC__out boolean *replaced);
    HRESULT ( STDMETHODCALLTYPE *Remove )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This,/* [in] */ HSTRING key);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic * This);
    END_INTERFACE
} __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl;

interface __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
{
    CONST_VTBL struct __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemanticVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Lookup(This,key,value)	\
    ( (This)->lpVtbl -> Lookup(This,key,value) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_HasKey(This,key,found)	\
    ( (This)->lpVtbl -> HasKey(This,key,found) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Insert(This,key,value,replaced)	\
    ( (This)->lpVtbl -> Insert(This,key,value,replaced) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Remove(This,key)	\
    ( (This)->lpVtbl -> Remove(This,key) ) 

#define __FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 
#endif /* COBJMACROS */



#endif // ____FIMap_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic_INTERFACE_DEFINED__



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

typedef struct __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
            /* [in] */ __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl;

interface __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode;

typedef struct __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
            /* [in] */ __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl;

interface __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__)
#define ____FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

typedef interface __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent;

typedef struct __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [out] */ __RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneComponent **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This, /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * *value);

    END_INTERFACE
} __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl;

interface __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent
{
    CONST_VTBL struct __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponentVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__)
#define ____FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

typedef interface __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode;

typedef struct __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [out] */ __RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ unsigned int index,
        /* [retval][out] */ __RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *item);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
        __RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [retval][out] */ __RPC__out unsigned int *size);

    HRESULT ( STDMETHODCALLTYPE *GetView )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [retval][out] */ __RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CComposition__CScenes__CSceneNode **view);

    HRESULT ( STDMETHODCALLTYPE *IndexOf )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * item,
        /* [out] */ __RPC__out unsigned int *index,
        /* [retval][out] */ __RPC__out boolean *found);

    HRESULT ( STDMETHODCALLTYPE *SetAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * item);

    HRESULT ( STDMETHODCALLTYPE *InsertAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ unsigned int index,
        /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * item);

    HRESULT ( STDMETHODCALLTYPE *RemoveAt )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [in] */ unsigned int index);
    HRESULT ( STDMETHODCALLTYPE *Append )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This, /* [in] */ __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * item);
    HRESULT ( STDMETHODCALLTYPE *RemoveAtEnd )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);
    HRESULT ( STDMETHODCALLTYPE *Clear )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ unsigned int startIndex,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    HRESULT ( STDMETHODCALLTYPE *ReplaceAll )(__RPC__in __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * This,
        /* [in] */ unsigned int count,
        /* [size_is][in] */ __RPC__in_ecount_full(count) __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * *value);

    END_INTERFACE
} __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl;

interface __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode
{
    CONST_VTBL struct __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNodeVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetView(This,view)	\
    ( (This)->lpVtbl -> GetView(This,view) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_SetAt(This,index,item)	\
    ( (This)->lpVtbl -> SetAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_InsertAt(This,index,item)	\
    ( (This)->lpVtbl -> InsertAt(This,index,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_RemoveAt(This,index)	\
    ( (This)->lpVtbl -> RemoveAt(This,index) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_Append(This,item)	\
    ( (This)->lpVtbl -> Append(This,item) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_RemoveAtEnd(This)	\
    ( (This)->lpVtbl -> RemoveAtEnd(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_Clear(This)	\
    ( (This)->lpVtbl -> Clear(This) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#define __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_ReplaceAll(This,count,value)	\
    ( (This)->lpVtbl -> ReplaceAll(This,count,value) ) 

#endif /* COBJMACROS */



#endif // ____FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


#ifndef ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIMemoryBuffer __x_ABI_CWindows_CFoundation_CIMemoryBuffer;

#endif // ____x_ABI_CWindows_CFoundation_CIMemoryBuffer_FWD_DEFINED__





typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion;


typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3 __x_ABI_CWindows_CFoundation_CNumerics_CVector3;


typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector4 __x_ABI_CWindows_CFoundation_CNumerics_CVector4;








typedef enum __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat;


typedef enum __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPrimitiveTopology __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPrimitiveTopology;





typedef enum __x_ABI_CWindows_CUI_CComposition_CCompositionBitmapInterpolationMode __x_ABI_CWindows_CUI_CComposition_CCompositionBitmapInterpolationMode;

#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CICompositor __x_ABI_CWindows_CUI_CComposition_CICompositor;

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositionSurface_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositionSurface_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CICompositionSurface __x_ABI_CWindows_CUI_CComposition_CICompositionSurface;

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositionSurface_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAlphaMode __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAlphaMode;


typedef enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic;


typedef enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneComponentType __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneComponentType;


typedef enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode;

























































/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneAlphaMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAlphaMode
{
    SceneAlphaMode_Opaque = 0,
    SceneAlphaMode_AlphaTest = 1,
    SceneAlphaMode_Blend = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneAttributeSemantic
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic
{
    SceneAttributeSemantic_Index = 0,
    SceneAttributeSemantic_Vertex = 1,
    SceneAttributeSemantic_Normal = 2,
    SceneAttributeSemantic_TexCoord0 = 3,
    SceneAttributeSemantic_TexCoord1 = 4,
    SceneAttributeSemantic_Color = 5,
    SceneAttributeSemantic_Tangent = 6,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneComponentType
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneComponentType
{
    SceneComponentType_MeshRendererComponent = 0,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Scenes.SceneWrappingMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode
{
    SceneWrappingMode_ClampToEdge = 0,
    SceneWrappingMode_MirroredRepeat = 1,
    SceneWrappingMode_Repeat = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneBoundingBox
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneBoundingBox
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneBoundingBox[] = L"Windows.UI.Composition.Scenes.ISceneBoundingBox";
/* [object, uuid("5D8FFC70-C618-4083-8251-9962593114AA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBoxVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Center )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Extents )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Max )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Min )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Size )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBoxVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBoxVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_get_Center(This,value) \
    ( (This)->lpVtbl->get_Center(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_get_Extents(This,value) \
    ( (This)->lpVtbl->get_Extents(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_get_Max(This,value) \
    ( (This)->lpVtbl->get_Max(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_get_Min(This,value) \
    ( (This)->lpVtbl->get_Min(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_get_Size(This,value) \
    ( (This)->lpVtbl->get_Size(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneComponent[] = L"Windows.UI.Composition.Scenes.ISceneComponent";
/* [object, uuid("AE20FC96-226C-44BD-95CB-DD5ED9EBE9A5"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ComponentType )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneComponentType * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_get_ComponentType(This,value) \
    ( (This)->lpVtbl->get_ComponentType(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneComponentCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneComponentCollection
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneComponentCollection[] = L"Windows.UI.Composition.Scenes.ISceneComponentCollection";
/* [object, uuid("C483791C-5F46-45E4-B666-A3D2259F9B2E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollectionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollectionVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollectionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentCollection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneComponentFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneComponentFactory[] = L"Windows.UI.Composition.Scenes.ISceneComponentFactory";
/* [object, uuid("5FBC5574-DDD8-5889-AB5B-D8FA716E7C9E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponentFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterial[] = L"Windows.UI.Composition.Scenes.ISceneMaterial";
/* [object, uuid("8CA74B7C-30DF-4E07-9490-37875AF1A123"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterialFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterialFactory[] = L"Windows.UI.Composition.Scenes.ISceneMaterialFactory";
/* [object, uuid("67536C19-A707-5254-A495-7FDC799893B9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterialInput[] = L"Windows.UI.Composition.Scenes.ISceneMaterialInput";
/* [object, uuid("422A1642-1EF1-485C-97E9-AE6F95AD812F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMaterialInputFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMaterialInputFactory[] = L"Windows.UI.Composition.Scenes.ISceneMaterialInputFactory";
/* [object, uuid("A88FEB74-7D0A-5E4C-A748-1015AF9CA74F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInputFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMesh
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMesh
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMesh[] = L"Windows.UI.Composition.Scenes.ISceneMesh";
/* [object, uuid("EE9A1530-1155-4C0C-92BD-40020CF78347"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Bounds )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneBoundingBox * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PrimitiveTopology )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDirectX_CDirectXPrimitiveTopology * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PrimitiveTopology )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
        /* [in] */__x_ABI_CWindows_CGraphics_CDirectX_CDirectXPrimitiveTopology value
        );
    HRESULT ( STDMETHODCALLTYPE *FillMeshAttribute )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAttributeSemantic semantic,
        /* [in] */__x_ABI_CWindows_CGraphics_CDirectX_CDirectXPixelFormat format,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CFoundation_CIMemoryBuffer * memory
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_get_Bounds(This,value) \
    ( (This)->lpVtbl->get_Bounds(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_get_PrimitiveTopology(This,value) \
    ( (This)->lpVtbl->get_PrimitiveTopology(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_put_PrimitiveTopology(This,value) \
    ( (This)->lpVtbl->put_PrimitiveTopology(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_FillMeshAttribute(This,semantic,format,memory) \
    ( (This)->lpVtbl->FillMeshAttribute(This,semantic,format,memory) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshMaterialAttributeMap[] = L"Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap";
/* [object, uuid("CE843171-3D43-4855-AA69-31FF988D049D"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMapVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMapVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMapVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMeshRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent[] = L"Windows.UI.Composition.Scenes.ISceneMeshRendererComponent";
/* [object, uuid("9929F7E3-6364-477E-98FE-74ED9FD4C2DE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Material )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Material )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterial * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Mesh )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Mesh )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UVMappings )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshMaterialAttributeMap * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_get_Material(This,value) \
    ( (This)->lpVtbl->get_Material(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_put_Material(This,value) \
    ( (This)->lpVtbl->put_Material(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_get_Mesh(This,value) \
    ( (This)->lpVtbl->get_Mesh(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_put_Mesh(This,value) \
    ( (This)->lpVtbl->put_Mesh(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_get_UVMappings(This,value) \
    ( (This)->lpVtbl->get_UVMappings(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMeshRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshRendererComponentStatics[] = L"Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics";
/* [object, uuid("4954F37A-4459-4521-BD6E-2B38B8D711EA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponent * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshRendererComponentStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMeshStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMesh
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMeshStatics[] = L"Windows.UI.Composition.Scenes.ISceneMeshStatics";
/* [object, uuid("8412316C-7B57-473F-966B-81DC277B1751"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMesh * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMeshStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial[] = L"Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial";
/* [object, uuid("C1D91446-799C-429E-A4E4-5DA645F18E61"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BaseColorInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BaseColorInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BaseColorFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector4 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BaseColorFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector4 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MetallicFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MetallicFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MetallicRoughnessInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MetallicRoughnessInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RoughnessFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RoughnessFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * This,
        /* [in] */FLOAT value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_get_BaseColorInput(This,value) \
    ( (This)->lpVtbl->get_BaseColorInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_put_BaseColorInput(This,value) \
    ( (This)->lpVtbl->put_BaseColorInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_get_BaseColorFactor(This,value) \
    ( (This)->lpVtbl->get_BaseColorFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_put_BaseColorFactor(This,value) \
    ( (This)->lpVtbl->put_BaseColorFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_get_MetallicFactor(This,value) \
    ( (This)->lpVtbl->get_MetallicFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_put_MetallicFactor(This,value) \
    ( (This)->lpVtbl->put_MetallicFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_get_MetallicRoughnessInput(This,value) \
    ( (This)->lpVtbl->get_MetallicRoughnessInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_put_MetallicRoughnessInput(This,value) \
    ( (This)->lpVtbl->put_MetallicRoughnessInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_get_RoughnessFactor(This,value) \
    ( (This)->lpVtbl->get_RoughnessFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_put_RoughnessFactor(This,value) \
    ( (This)->lpVtbl->put_RoughnessFactor(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterialStatics[] = L"Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics";
/* [object, uuid("3BDDCA50-6D9D-4531-8DC4-B27E3E49B7AB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterial * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMetallicRoughnessMaterialStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneModelTransform
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneModelTransform
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneModelTransform[] = L"Windows.UI.Composition.Scenes.ISceneModelTransform";
/* [object, uuid("C05576C2-32B1-4269-980D-B98537100AE4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransformVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Orientation )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CQuaternion * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Orientation )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CQuaternion value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RotationAngle )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RotationAngle )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RotationAngleInDegrees )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RotationAngleInDegrees )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RotationAxis )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RotationAxis )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Scale )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Scale )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Translation )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Translation )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransformVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransformVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_get_Orientation(This,value) \
    ( (This)->lpVtbl->get_Orientation(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_put_Orientation(This,value) \
    ( (This)->lpVtbl->put_Orientation(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_get_RotationAngle(This,value) \
    ( (This)->lpVtbl->get_RotationAngle(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_put_RotationAngle(This,value) \
    ( (This)->lpVtbl->put_RotationAngle(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_get_RotationAngleInDegrees(This,value) \
    ( (This)->lpVtbl->get_RotationAngleInDegrees(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_put_RotationAngleInDegrees(This,value) \
    ( (This)->lpVtbl->put_RotationAngleInDegrees(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_get_RotationAxis(This,value) \
    ( (This)->lpVtbl->get_RotationAxis(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_put_RotationAxis(This,value) \
    ( (This)->lpVtbl->put_RotationAxis(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_get_Scale(This,value) \
    ( (This)->lpVtbl->get_Scale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_put_Scale(This,value) \
    ( (This)->lpVtbl->put_Scale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_get_Translation(This,value) \
    ( (This)->lpVtbl->get_Translation(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_put_Translation(This,value) \
    ( (This)->lpVtbl->put_Translation(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneNode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneNode
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneNode[] = L"Windows.UI.Composition.Scenes.ISceneNode";
/* [object, uuid("ACF2C247-F307-4581-9C41-AF2E29C3B016"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Children )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneNode * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Components )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVector_1_Windows__CUI__CComposition__CScenes__CSceneComponent * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Parent )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Transform )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneModelTransform * * value
        );
    HRESULT ( STDMETHODCALLTYPE *FindFirstComponentOfType )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CScenes_CSceneComponentType value,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneComponent * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_get_Children(This,value) \
    ( (This)->lpVtbl->get_Children(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_get_Components(This,value) \
    ( (This)->lpVtbl->get_Components(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_get_Parent(This,value) \
    ( (This)->lpVtbl->get_Parent(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_get_Transform(This,value) \
    ( (This)->lpVtbl->get_Transform(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_FindFirstComponentOfType(This,value,result) \
    ( (This)->lpVtbl->FindFirstComponentOfType(This,value,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneNodeCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneNodeCollection
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneNodeCollection[] = L"Windows.UI.Composition.Scenes.ISceneNodeCollection";
/* [object, uuid("29ADA101-2DD9-4332-BE63-60D2CF4269F2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollectionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollectionVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollectionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeCollection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneNodeStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneNode
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneNodeStatics[] = L"Windows.UI.Composition.Scenes.ISceneNodeStatics";
/* [object, uuid("579A0FAA-BE9D-4210-908C-93D15FEED0B7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNodeStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneObject
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneObject
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneObject[] = L"Windows.UI.Composition.Scenes.ISceneObject";
/* [object, uuid("1E94249B-0F1B-49EB-A819-877D8450005B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObject_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneObjectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneObject
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneObjectFactory[] = L"Windows.UI.Composition.Scenes.ISceneObjectFactory";
/* [object, uuid("14FE799A-33E4-52EF-956C-44229D21F2C1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneObjectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.IScenePbrMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.ScenePbrMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_IScenePbrMaterial[] = L"Windows.UI.Composition.Scenes.IScenePbrMaterial";
/* [object, uuid("AAB6EBBE-D680-46DF-8294-B6800A9F95E7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AlphaCutoff )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AlphaCutoff )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AlphaMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAlphaMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_AlphaMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CScenes_CSceneAlphaMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EmissiveInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_EmissiveInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_EmissiveFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_EmissiveFactor )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsDoubleSided )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsDoubleSided )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NormalInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_NormalInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NormalScale )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_NormalScale )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OcclusionInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_OcclusionInput )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneMaterialInput * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OcclusionStrength )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_OcclusionStrength )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial * This,
        /* [in] */FLOAT value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_AlphaCutoff(This,value) \
    ( (This)->lpVtbl->get_AlphaCutoff(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_AlphaCutoff(This,value) \
    ( (This)->lpVtbl->put_AlphaCutoff(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_AlphaMode(This,value) \
    ( (This)->lpVtbl->get_AlphaMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_AlphaMode(This,value) \
    ( (This)->lpVtbl->put_AlphaMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_EmissiveInput(This,value) \
    ( (This)->lpVtbl->get_EmissiveInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_EmissiveInput(This,value) \
    ( (This)->lpVtbl->put_EmissiveInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_EmissiveFactor(This,value) \
    ( (This)->lpVtbl->get_EmissiveFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_EmissiveFactor(This,value) \
    ( (This)->lpVtbl->put_EmissiveFactor(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_IsDoubleSided(This,value) \
    ( (This)->lpVtbl->get_IsDoubleSided(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_IsDoubleSided(This,value) \
    ( (This)->lpVtbl->put_IsDoubleSided(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_NormalInput(This,value) \
    ( (This)->lpVtbl->get_NormalInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_NormalInput(This,value) \
    ( (This)->lpVtbl->put_NormalInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_NormalScale(This,value) \
    ( (This)->lpVtbl->get_NormalScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_NormalScale(This,value) \
    ( (This)->lpVtbl->put_NormalScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_OcclusionInput(This,value) \
    ( (This)->lpVtbl->get_OcclusionInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_OcclusionInput(This,value) \
    ( (This)->lpVtbl->put_OcclusionInput(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_get_OcclusionStrength(This,value) \
    ( (This)->lpVtbl->get_OcclusionStrength(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_put_OcclusionStrength(This,value) \
    ( (This)->lpVtbl->put_OcclusionStrength(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterial_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.IScenePbrMaterialFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.ScenePbrMaterial
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_IScenePbrMaterialFactory[] = L"Windows.UI.Composition.Scenes.IScenePbrMaterialFactory";
/* [object, uuid("2E3F3DFE-0B85-5727-B5BE-B7D3CBAC37FA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CIScenePbrMaterialFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneRendererComponent[] = L"Windows.UI.Composition.Scenes.ISceneRendererComponent";
/* [object, uuid("F1ACB857-CF4F-4025-9B25-A2D1944CF507"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponent_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneRendererComponentFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneRendererComponent
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneRendererComponentFactory[] = L"Windows.UI.Composition.Scenes.ISceneRendererComponentFactory";
/* [object, uuid("1DB6ED6C-AA2C-5967-9035-56352DC69658"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneRendererComponentFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput[] = L"Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput";
/* [object, uuid("9937DA5C-A9CA-4CFC-B3AA-088356518742"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BitmapInterpolationMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CCompositionBitmapInterpolationMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_BitmapInterpolationMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CCompositionBitmapInterpolationMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Surface )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CICompositionSurface * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Surface )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositionSurface * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WrappingUMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_WrappingUMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WrappingVMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_WrappingVMode )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CScenes_CSceneWrappingMode value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_get_BitmapInterpolationMode(This,value) \
    ( (This)->lpVtbl->get_BitmapInterpolationMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_put_BitmapInterpolationMode(This,value) \
    ( (This)->lpVtbl->put_BitmapInterpolationMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_get_Surface(This,value) \
    ( (This)->lpVtbl->get_Surface(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_put_Surface(This,value) \
    ( (This)->lpVtbl->put_Surface(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_get_WrappingUMode(This,value) \
    ( (This)->lpVtbl->get_WrappingUMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_put_WrappingUMode(This,value) \
    ( (This)->lpVtbl->put_WrappingUMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_get_WrappingVMode(This,value) \
    ( (This)->lpVtbl->get_WrappingVMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_put_WrappingVMode(This,value) \
    ( (This)->lpVtbl->put_WrappingVMode(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInputStatics[] = L"Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics";
/* [object, uuid("5A2394D3-6429-4589-BBCF-B84F4F3CFBFE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInput * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneSurfaceMaterialInputStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneVisual
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneVisual
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneVisual[] = L"Windows.UI.Composition.Scenes.ISceneVisual";
/* [object, uuid("8E672C1E-D734-47B1-BE14-3D694FFA4301"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Root )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Root )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneNode * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_get_Root(This,value) \
    ( (This)->lpVtbl->get_Root(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_put_Root(This,value) \
    ( (This)->lpVtbl->put_Root(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Scenes.ISceneVisualStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Scenes.SceneVisual
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Scenes_ISceneVisualStatics[] = L"Windows.UI.Composition.Scenes.ISceneVisualStatics";
/* [object, uuid("B8347E9A-50AA-4527-8D34-DE4CB8EA88B4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisual * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CScenes_CISceneVisualStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneBoundingBox
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneBoundingBox ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneBoundingBox_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneBoundingBox_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneBoundingBox[] = L"Windows.UI.Composition.Scenes.SceneBoundingBox";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneComponent ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponent_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponent_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneComponent[] = L"Windows.UI.Composition.Scenes.SceneComponent";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneComponentCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneComponentCollection
 *    Windows.Foundation.Collections.IVector_1_Windows.UI.Composition.Scenes.SceneComponent ** Default Interface **
 *    Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Scenes.SceneComponent
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponentCollection_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneComponentCollection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneComponentCollection[] = L"Windows.UI.Composition.Scenes.SceneComponentCollection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMaterial ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterial_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterial_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMaterial[] = L"Windows.UI.Composition.Scenes.SceneMaterial";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMaterialInput ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterialInput_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMaterialInput_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMaterialInput[] = L"Windows.UI.Composition.Scenes.SceneMaterialInput";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMesh
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneMeshStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMesh ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMesh_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMesh_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMesh[] = L"Windows.UI.Composition.Scenes.SceneMesh";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap ** Default Interface **
 *    Windows.Foundation.Collections.IMap_2_HSTRING,Windows.UI.Composition.Scenes.SceneAttributeSemantic
 *    Windows.Foundation.Collections.IIterable_1___FIKeyValuePair_2_HSTRING_Windows__CUI__CComposition__CScenes__CSceneAttributeSemantic
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshMaterialAttributeMap_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshMaterialAttributeMap_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMeshMaterialAttributeMap[] = L"Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMeshRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMeshRendererComponent ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshRendererComponent_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMeshRendererComponent_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMeshRendererComponent[] = L"Windows.UI.Composition.Scenes.SceneMeshRendererComponent";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMetallicRoughnessMaterial_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneMetallicRoughnessMaterial_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneMetallicRoughnessMaterial[] = L"Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneModelTransform
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneModelTransform ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneModelTransform_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneModelTransform_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneModelTransform[] = L"Windows.UI.Composition.Scenes.SceneModelTransform";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneNode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneNodeStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneNode ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNode_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNode_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneNode[] = L"Windows.UI.Composition.Scenes.SceneNode";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneNodeCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneNodeCollection
 *    Windows.Foundation.Collections.IVector_1_Windows.UI.Composition.Scenes.SceneNode ** Default Interface **
 *    Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Scenes.SceneNode
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNodeCollection_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneNodeCollection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneNodeCollection[] = L"Windows.UI.Composition.Scenes.SceneNodeCollection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneObject
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneObject ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneObject_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneObject_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneObject[] = L"Windows.UI.Composition.Scenes.SceneObject";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.ScenePbrMaterial
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.IScenePbrMaterial ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_ScenePbrMaterial_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_ScenePbrMaterial_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_ScenePbrMaterial[] = L"Windows.UI.Composition.Scenes.ScenePbrMaterial";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneRendererComponent
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneRendererComponent ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneRendererComponent_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneRendererComponent_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneRendererComponent[] = L"Windows.UI.Composition.Scenes.SceneRendererComponent";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneSurfaceMaterialInput_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneSurfaceMaterialInput_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneSurfaceMaterialInput[] = L"Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Scenes.SceneVisual
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Scenes.ISceneVisualStatics interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Scenes.ISceneVisual ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneVisual_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Scenes_SceneVisual_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Scenes_SceneVisual[] = L"Windows.UI.Composition.Scenes.SceneVisual";
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
#endif // __windows2Eui2Ecomposition2Escenes_p_h__

#endif // __windows2Eui2Ecomposition2Escenes_h__
